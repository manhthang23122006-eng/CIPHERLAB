from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


def generate_keys():
    key = RSA.generate(2048)

    private_key = key.export_key().decode("utf-8")

    public_key = key.publickey().export_key().decode("utf-8")

    return public_key, private_key


def encrypt_rsa(text, public_key):
    key = RSA.import_key(public_key)

    cipher = PKCS1_OAEP.new(key)

    encrypted = cipher.encrypt(
        text.encode("utf-8")
    )

    return base64.b64encode(
        encrypted
    ).decode("utf-8")


def decrypt_rsa(ciphertext, private_key):
    key = RSA.import_key(private_key)

    cipher = PKCS1_OAEP.new(key)

    encrypted = base64.b64decode(ciphertext)

    decrypted = cipher.decrypt(encrypted)

    return decrypted.decode("utf-8")