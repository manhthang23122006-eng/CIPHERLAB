from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import base64


def pad(data):
    padding = DES.block_size - len(data) % DES.block_size
    return data + bytes([padding]) * padding


def unpad(data):
    return data[:-data[-1]]


def create_key(key):
    key = key.encode("utf-8")

    if len(key) < 8:
        key = key.ljust(8, b"0")

    return key[:8]


def encrypt_des(text, key):

    key = create_key(key)

    iv = get_random_bytes(8)

    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )

    encrypted = cipher.encrypt(
        pad(text.encode("utf-8"))
    )

    result = iv + encrypted

    return base64.b64encode(result).decode("utf-8")


def decrypt_des(ciphertext, key):

    key = create_key(key)

    data = base64.b64decode(ciphertext)

    iv = data[:8]

    encrypted = data[8:]

    cipher = DES.new(
        key,
        DES.MODE_CBC,
        iv
    )

    decrypted = cipher.decrypt(encrypted)

    return unpad(decrypted).decode("utf-8")