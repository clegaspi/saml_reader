from cryptography.fernet import Fernet

_crypto = Fernet(Fernet.generate_key())
CRYPTO_STATE = str(Fernet.generate_key(), "UTF-8")


def encrypt_string(data: str) -> str:
    if not data:
        return ""
    return str(_crypto.encrypt(bytes(data, "UTF-8")), "UTF-8")


def decrypt_string(data: str) -> str:
    if not data:
        return ""
    return str(_crypto.decrypt(bytes(data, "UTF-8")), "UTF-8")
