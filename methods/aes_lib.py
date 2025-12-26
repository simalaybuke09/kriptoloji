from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class AESLib:
    def encrypt(self, plaintext, key_bytes, iv_bytes):
        if len(key_bytes) != 16: raise ValueError("AES Anahtarı 16 byte olmalıdır.")
        if len(iv_bytes) != 16: raise ValueError("AES IV 16 byte olmalıdır.")
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        return (encryptor.update(padded_data) + encryptor.finalize()).hex()

    def decrypt(self, ciphertext_hex, key_bytes, iv_bytes):
        if len(key_bytes) != 16: raise ValueError("AES Anahtarı 16 byte olmalıdır.")
        if len(iv_bytes) != 16: raise ValueError("AES IV 16 byte olmalıdır.")
        ciphertext = bytes.fromhex(ciphertext_hex)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(decrypted_padded_data) + unpadder.finalize()).decode('utf-8')