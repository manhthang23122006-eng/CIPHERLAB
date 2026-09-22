import base64
import secrets
import ast


# ==============================
# GENERATE ELGAMAL KEYS
# ==============================

def generate_keys():

    p = 467

    g = 2

    private_key = secrets.randbelow(p - 2) + 1

    public_key = pow(
        g,
        private_key,
        p
    )

    return {
        "p": p,
        "g": g,
        "public_key": public_key,
        "private_key": private_key
    }


# ==============================
# ELGAMAL ENCRYPT
# ==============================

def encrypt_elgamal(text, keys):

    p = keys["p"]

    g = keys["g"]

    public_key = keys["public_key"]

    data = text.encode("utf-8")

    result = []

    for byte in data:

        k = secrets.randbelow(p - 2) + 1

        c1 = pow(
            g,
            k,
            p
        )

        shared = pow(
            public_key,
            k,
            p
        )

        c2 = (
            byte * shared
        ) % p

        result.append(
            (c1, c2)
        )

    encoded = str(
        result
    ).encode("utf-8")

    return base64.b64encode(
        encoded
    ).decode("utf-8")


# ==============================
# ELGAMAL DECRYPT
# ==============================

def decrypt_elgamal(ciphertext, keys):

    p = keys["p"]

    private_key = keys["private_key"]

    # Base64 decode
    decoded_bytes = base64.b64decode(
        ciphertext
    )

    # Decode phần danh sách cặp số
    decoded_text = decoded_bytes.decode(
        "utf-8"
    )

    # Chuyển chuỗi thành list
    pairs = ast.literal_eval(
        decoded_text
    )

    result = []

    for c1, c2 in pairs:

        shared = pow(
            c1,
            private_key,
            p
        )

        inverse = pow(
            shared,
            -1,
            p
        )

        byte = (
            c2 * inverse
        ) % p

        result.append(
            byte
        )

    return bytes(
        result
    ).decode("utf-8")