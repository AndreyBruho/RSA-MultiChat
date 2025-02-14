import random
import hashlib

def is_prime(n, k=5):
    """Проверяет, является ли число n простым."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def gcd_extended(a, b):
    """Расширенный алгоритм Евклида."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = gcd_extended(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    """Нахождение мультипликативного обратного по модулю."""
    gcd, x, y = gcd_extended(a, m)
    if gcd != 1:
        raise ValueError('Обратного элемента не существует')
    return x % m

def random_prime(bit_length):
    """Генерирует случайное простое число заданной длины."""
    while True:
        n = random.getrandbits(bit_length)
        if is_prime(n):
            return n
def generate_rsa_keys(key_length):
    """Генерирует пару открытого и закрытого ключей RSA."""
    # Генерация двух простых чисел p и q
    p = random_prime(key_length)
    q = random_prime(key_length)

    # Вычисление произведения p и q
    n = p * q

    # Вычисление функции Эйлера от n
    phi_n = (p - 1) * (q - 1)

    # Выбор открытой экспоненты e
    e = 65537  # Обычно используется 65537 (2^16 + 1)

    # Нахождение мультипликативного обратного к e по модулю phi_n
    d = mod_inverse(e, phi_n)

    # Возвращаем открытый и закрытый ключи
    return (e, n), (d, n)

def rsa_encrypt(message, public_key):
    """Шифрует сообщение с помощью открытого ключа."""
    e, n = public_key
    encrypted_message = [pow(ord(char), e, n) for char in message]
    return encrypted_message

def rsa_decrypt(encrypted_message, private_key):
    """Дешифрует сообщение с помощью закрытого ключа."""
    d, n = private_key
    decrypted_message = [chr(pow(char, d, n)) for char in encrypted_message]
    return ''.join(decrypted_message)
def rsa_sign(message, private_key):
    """Создает подпись для сообщения."""
    hash_value = hashlib.sha1(message.encode()).hexdigest()
    hash_int = int(hash_value, 16)
    d, n = private_key
    signature = pow(hash_int, d, n)
    return signature

def rsa_verify(message, signature, public_key):
    """Проверяет подпись для сообщения."""
    hash_value = hashlib.sha1(message.encode()).hexdigest()
    hash_int = int(hash_value, 16)
    e, n = public_key
    decrypted_signature = pow(signature, e, n)
    return decrypted_signature == hash_int