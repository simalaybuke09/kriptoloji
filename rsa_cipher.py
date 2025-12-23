from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

class RSACipher:
    def generate_keys(self):
        """2048-bit RSA Anahtar Çifti Üretir"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def save_public_key(self, public_key, filename):
        """Public Key'i PEM formatında dosyaya kaydeder"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(filename, 'wb') as f:
            f.write(pem)

    def load_public_key_from_bytes(self, pem_data):
        """Byte verisinden Public Key nesnesi oluşturur"""
        return serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )

    def encrypt_key(self, key_bytes, public_key):
        """Simetrik anahtarı (AES/DES) RSA Public Key ile şifreler"""
        encrypted = public_key.encrypt(
            key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_key(self, encrypted_key_bytes, private_key):
        """RSA Private Key ile şifrelenmiş simetrik anahtarı çözer"""
        original_key = private_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_key