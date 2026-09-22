from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64


def pad(data):
    padding = AES.block_size - len(data) % AES.block_size
    return data + bytes([padding]) * padding


def unpad(data):
    return data[:-data[-1]]


def encrypt_aes(text, key):
    key = key.encode("utf-8")

    if len(key) not in [16, 24, 32]:
        raise ValueError("Key AES phải có 16, 24 hoặc 32 ký tự.")

    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.encrypt(pad(text.encode("utf-8")))

    result = cipher.iv + encrypted

    return base64.b64encode(result).decode("utf-8")


def decrypt_aes(ciphertext, key):
    key = key.encode("utf-8")

    if len(key) not in [16, 24, 32]:
        raise ValueError("Key AES phải có 16, 24 hoặc 32 ký tự.")

    data = base64.b64decode(ciphertext)

    iv = data[:AES.block_size]
    encrypted = data[AES.block_size:]

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted = cipher.decrypt(encrypted)

    return unpad(decrypted).decode("utf-8")