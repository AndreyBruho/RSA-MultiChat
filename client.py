import socket
import time
import threading
import tkinter as tk
from tkinter import scrolledtext
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Создаем RSA ключи для клиента
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
client_public_key = client_private_key.public_key()

def on_closing(client_socket, root):
    # Закрываем сокет
    client_socket.close()
    # Завершаем работу приложения
    root.destroy()
def receive_messages(client_socket, text_area):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                decrypted_message = client_private_key.decrypt(
                    encrypted_message,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode('utf-8')
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, f"{decrypted_message}\n")
                text_area.yview(tk.END)
                text_area.config(state=tk.DISABLED)
        except Exception as e:
            print(f"An error occurred: {e}")
            client_socket.close()
            break

def send_messages(client_socket, server_public_key, message_entry, text_area, alias):
    message = f'{alias}: {message_entry.get()}'

    text_area.config(state=tk.NORMAL)
    text_area.insert(tk.END, f"{message}\n")
    text_area.yview(tk.END)
    text_area.config(state=tk.DISABLED)

    encrypted_message = server_public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(encrypted_message)
    client_socket.send(encrypted_message)
    message_entry.delete(0, tk.END)

def start_chat(ip, port, username, password, action, rt, error_label):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((ip, int(port)))
    except Exception as e:
        error_label.config(text="Connection error")
        return
    print(action)
    # Отправляем публичный ключ клиента на сервер
    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(client_public_key_pem)
    #time.sleep(1)
    # Получаем публичный ключ сервера
    server_public_key_pem = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(server_public_key_pem)
    time.sleep(1)
    print("Connected to the server.")
    print("Server public key received.")
    print(server_public_key)

    credentials = f"{action},{username},{password}"
    encrypted_credentials = server_public_key.encrypt(
        credentials.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Отправляем зашифрованные credentials на сервер
    client_socket.send(encrypted_credentials)
    #print(credentials)
    #print("Credentials sent")
    response = client_socket.recv(1024).decode('utf-8')
    #print(response)
    if response == "success":
        print("authorization successful")
        rt.destroy()
        # Создаем графический интерфейс чата
        root = tk.Tk()
        root.title("Chat Client")

        text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state=tk.DISABLED)
        text_area.pack(padx=20, pady=5, expand=True, fill='both')

        message_entry = tk.Entry(root)
        message_entry.pack(padx=20, pady=5, fill='x')

        send_button = tk.Button(root, text="Send",
                            command=lambda: send_messages(client_socket, server_public_key, message_entry, text_area, username))
        send_button.pack(padx=20, pady=5)

        # Запускаем потоки для приема и отправки сообщений
        receive_thread = threading.Thread(target=receive_messages, args=(client_socket, text_area))
        receive_thread.start()

        # Привязываем обработчик закрытия окна
        root.protocol("WM_DELETE_WINDOW", lambda: on_closing(client_socket, root))

        root.mainloop()

    elif response == "failure":
        error_label.config(text="Incorrect username or password")
        print("Incorrect username or password")
        client_socket.close()
    elif response == "exists":
        error_label.config(text="username already exists")
        print("username already exists")
        client_socket.close()


def main_screen():
    root = tk.Tk()
    root.title("Connect to Chat Server")

    root.geometry("300x350")

    tk.Label(root, text="IP Address:").pack(padx=20, pady=5)
    ip_entry = tk.Entry(root)
    ip_entry.pack(padx=20, pady=5)

    tk.Label(root, text="Port:").pack(padx=20, pady=5)
    port_entry = tk.Entry(root)
    port_entry.pack(padx=20, pady=5)

    tk.Label(root, text="Username:").pack(padx=20, pady=5)
    username_entry = tk.Entry(root)
    username_entry.pack(padx=20, pady=5)

    tk.Label(root, text="Password:").pack(padx=20, pady=5)
    password_entry = tk.Entry(root)
    password_entry.pack(padx=20, pady=5)

    error_label = tk.Label(root, text="", fg="red")
    error_label.pack(padx=20, pady=5)

    def login():
        ip = ip_entry.get()
        port = port_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        #root.destroy()
        start_chat(ip, port, username, password, "login", root, error_label)


    def signup():
        ip = ip_entry.get()
        port = port_entry.get()
        username = username_entry.get()
        password = password_entry.get()
        #root.destroy()
        start_chat(ip, port, username, password, "signup", root, error_label)

    # def connect():
    #     ip = ip_entry.get()
    #     port = port_entry.get()
    #     username = username_entry.get()
    #     root.destroy()
    #     start_chat(ip, port, username)
    #
    # connect_button = tk.Button(root, text="Connect", command=connect)
    # connect_button.pack(padx=20, pady=20)

    button_frame = tk.Frame(root)
    button_frame.pack(padx=20, pady=10)

    login_button = tk.Button(button_frame, text='Log In', command=login)
    login_button.pack(side=tk.LEFT, padx=10)
    signup_button = tk.Button(button_frame, text='Sign Up', command=signup)
    signup_button.pack(side=tk.LEFT, padx=10)
    root.mainloop()

if __name__ == "__main__":
    main_screen()