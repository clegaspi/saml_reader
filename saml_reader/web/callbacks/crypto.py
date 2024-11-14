from cryptography.fernet import Fernet

# Encryption object unique to this app session
_crypto = Fernet(Fernet.generate_key())
# A random key representing the above unique encryption object
CRYPTO_STATE = str(Fernet.generate_key(), "UTF-8")


def encrypt_string(data: str) -> str:
    """Encrypt a string with the key generated this session.

    Args:
        data (str): data to encrypt

    Returns:
        str: encrypted string
    """
    if not data:
        return ""
    return str(_crypto.encrypt(bytes(data, "UTF-8")), "UTF-8")


def decrypt_string(data: str) -> str:
    """Decrypt a string with the key generated this session.

    Args:
        data (str): data to decrypt

    Returns:
        str: decrypted string
    """
    if not data:
        return ""
    return str(_crypto.decrypt(bytes(data, "UTF-8")), "UTF-8")
