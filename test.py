import unittest
from server import *
from client import *
import socket
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Тестовый класс для проверки работы сервера и клиента
class ChatServerClientTest(unittest.TestCase):

    def setUp(self):
        # Запускаем сервер в отдельном потоке
        self.server_thread = threading.Thread(target=start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(1)  # Даем серверу немного времени для запуска

    def tearDown(self):
        # Останавливаем сервер после выполнения тестов
        stop_server()

    def test_signup_and_login(self):
        # Проверка регистрации нового пользователя
        self.assertTrue(self.perform_signup('testuser', 'password123'))
        # Проверка повторной регистрации того же пользователя (должен получить "exists")
        self.assertFalse(self.perform_signup('testuser', 'password123'))
        # Проверка успешного логина
        self.assertTrue(self.perform_login('testuser', 'password123'))
        # Проверка неудачного логина с неправильным паролем
        self.assertFalse(self.perform_login('testuser', 'wrongpassword'))

    def perform_signup(self, username, password):
        return self.perform_auth_action(username, password, "signup")

    def perform_login(self, username, password):
        return self.perform_auth_action(username, password, "login")

    def perform_auth_action(self, username, password, action):
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(("127.0.0.1", 12345))

            # Отправляем публичный ключ клиента на сервер
            client_public_key_pem = client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(client_public_key_pem)

            # Получаем публичный ключ сервера
            server_public_key_pem = client_socket.recv(1024)
            server_public_key = serialization.load_pem_public_key(server_public_key_pem)

            time.sleep(1)

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

            response = client_socket.recv(1024).decode('utf-8')
            client_socket.close()
            return response == "success"
        except Exception as e:
            print(f"Error during {action}: {e}")
            return False

    def test_message_exchange(self):
        # Проверка обмена сообщениями между двумя клиентами
        client1 = self.create_client("user1", "pass1")
        client2 = self.create_client("user2", "pass2")

        client1.send_message("Hello from user1")
        received_message = client2.receive_message()
        self.assertEqual(received_message, "Hello from user1")

        client2.send_message("Hello from user2")
        received_message = client1.receive_message()
        self.assertEqual(received_message, "Hello from user2")

        client1.close()
        client2.close()

    def create_client(self, username, password):
        #print("hi")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(("127.0.0.1", 12345))
        client_public_key_pem = client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        client_socket.send(client_public_key_pem)
        server_public_key_pem = client_socket.recv(1024)
        time.sleep(1)
        server_public_key = serialization.load_pem_public_key(server_public_key_pem)
        credentials = f"signup,{username},{password}"
        encrypted_credentials = server_public_key.encrypt(
            credentials.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        client_socket.send(encrypted_credentials)
        print(credentials)
        response = client_socket.recv(1024).decode('utf-8')
        print(response)
        if response == "success":
            return ClientWrapper(client_socket, client_private_key)
        else:
            raise Exception("Failed to create client")

class ClientWrapper:
    def __init__(self, client_socket, private_key):
        self.client_socket = client_socket
        self.private_key = private_key

    def send_message(self, message):
        encrypted_message = server_public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        self.client_socket.send(encrypted_message)

    def receive_message(self):
        encrypted_message = self.client_socket.recv(1024)
        return self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode('utf-8')

    def close(self):
        self.client_socket.close()


if __name__ == "__main__":
    unittest.main()