import socket
import threading
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Создаем RSA ключи для сервера
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
server_public_key = server_private_key.public_key()

# Серийный ключ
server_public_key_pem = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

clients = {}
addresses = []
USER_FILE = "user_credentials.txt"
server_running = False
server = None





def load_users():
    users = {}
    try:
        with open(USER_FILE, "r") as file:
            for line in file:
                username, password = line.strip().split(",")
                users[username] = password
    except FileNotFoundError:
        pass
    return users


def save_user(username, password):
    with open(USER_FILE, "a") as file:
        file.write(f"{username},{password}\n")
    global users
    users = load_users()



SECRET_KEY = 'my_secret_key'

def xor_encrypt_decrypt(data: str, key: str) -> str:
    """Простое XOR шифрование/дешифрование."""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

# def load_users():
#     users = {}
#     try:
#         with open(USER_FILE, "r") as file:
#             for line in file:
#                 encrypted_username, encrypted_password = line.strip().split(",")
#                 username = xor_encrypt_decrypt(encrypted_username, SECRET_KEY)
#                 password = xor_encrypt_decrypt(encrypted_password, SECRET_KEY)
#                 users[username] = password
#                 print(users)
#     except FileNotFoundError:
#         pass
#     return users
#
# def save_user(username, password):
#     encrypted_username = xor_encrypt_decrypt(username, SECRET_KEY)
#     encrypted_password = xor_encrypt_decrypt(password, SECRET_KEY)
#     with open(USER_FILE, "a") as file:
#         file.write(f"{encrypted_username},{encrypted_password}\n")
#     users = load_users()

users = load_users()


def handle_client(client_socket):
    code = False
    # Получаем публичный ключ клиента
    try:
        client_public_key_pem = client_socket.recv(1024)
        if not client_public_key_pem:
            raise ConnectionResetError("Client disconnected")
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)
    except Exception as e:
        print(f"Error receiving client's public key: {e}")
        remove(client_socket)
        return

    while True:
        try:
            encrypted_credentials = client_socket.recv(1024)
            if not encrypted_credentials:
                raise ConnectionResetError("Client disconnected")

            credentials = server_private_key.decrypt(
                encrypted_credentials,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode('utf-8')
            action, username, password = credentials.split(",")
            print(action)
            if action == "login":
                if username in users and users[username] == password:
                    client_socket.send("success".encode('utf-8'))
                    clients[client_socket] = client_public_key
                    break
                else:
                    client_socket.send("failure".encode('utf-8'))
            elif action == "signup":
                if username in users:
                    client_socket.send("exists".encode('utf-8'))
                else:
                    save_user(username, password)
                    client_socket.send("success".encode('utf-8'))
                    clients[client_socket] = client_public_key
                    break
        except Exception as e:
            print(f"Error during authentication: {e}")
            remove(client_socket)
            return

    while True:
        try:
            message = client_socket.recv(1024)
            if not message:
                raise ConnectionResetError("Client disconnected")

            # Расшифровываем сообщение с помощью приватного ключа сервера
            decrypted_message = server_private_key.decrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            broadcast(decrypted_message, client_socket)
        except (ConnectionResetError, ConnectionAbortedError) as e:
            print(f"Client disconnected: {e}")
            remove(client_socket)
            break
        except Exception as e:
            print(f"Error: {e}")
            remove(client_socket)
            break


def broadcast(message, connection):
    for client_socket, client_public_key in clients.items():
        if client_socket != connection:
            try:
                encrypted_message = client_public_key.encrypt(
                    message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                client_socket.send(encrypted_message)
            except Exception as e:
                print(f"Error sending message: {e}")
                remove(client_socket)


def remove(connection):
    if connection in clients:
        del clients[connection]
        connection.close()


def start_server():
    global server_running, server
    if not server_running:
        server_running = True
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 12345))
        server.listen(5)
        print("Server started and listening...")

        while server_running:
            try:
                client_socket, client_address = server.accept()
                print(f"Connection from {client_address} has been established.")

                # Отправляем клиенту публичный ключ сервера
                client_socket.send(server_public_key_pem)

                addresses.append(client_address)

                client_thread = threading.Thread(target=handle_client, args=(client_socket,))
                client_thread.start()
            except Exception as e:
                print(f"Error accepting connections: {e}")
                break


def stop_server():
    global server_running, server
    server_running = False
    if server:
        server.close()
    print("Server stopped.")


def start_server_thread(error_label):
    server_thread = threading.Thread(target=start_server)
    error_label.config(text="Server is running", fg="green")
    server_thread.start()


def create_gui():
    root = tk.Tk()
    root.title("Chat Server Control")
    root.geometry("200x200")
    start_button = tk.Button(root, text="Start Server", command=lambda: start_server_thread(error_label))
    start_button.pack(padx=25, pady=25)

    stop_button = tk.Button(root, text="Stop Server", command=lambda: [stop_server(), error_label.config(text="Server is not working", fg="red")])
    stop_button.pack(padx=25, pady=25)
    error_label = tk.Label(root, text="Server is not working", fg="red")
    error_label.pack(padx=20, pady=5)

    root.protocol("WM_DELETE_WINDOW", lambda: [stop_server(), root.destroy()])
    root.mainloop()


if __name__ == "__main__":
    create_gui()
