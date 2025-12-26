from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class ECCCipher:
    def generate_keys(self):
        """SECP256R1 Eğrisi üzerinde ECC Anahtar Çifti Üretir"""
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
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

    def encrypt_key(self, key_bytes, peer_public_key):
        """
        Simetrik anahtarı (AES/DES) ECC Public Key ile şifreler (ECIES benzeri yapı).
        1. Geçici (Ephemeral) bir ECC anahtar çifti üretilir.
        2. ECDH ile ortak sır (shared secret) oluşturulur.
        3. Ortak sır kullanılarak HKDF ile şifreleme anahtarı türetilir.
        4. Simetrik anahtar AES-GCM ile şifrelenir.
        """
        # Geçici anahtar çifti üret
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ephemeral_public_key = ephemeral_private_key.public_key()
        
        # ECDH ile ortak sırrı hesapla
        shared_key = ephemeral_private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Anahtar türetme (HKDF)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'ecc_handshake',
            backend=default_backend()
        ).derive(shared_key)
        
        # Veriyi şifrele (AES-GCM)
        aesgcm = AESGCM(derived_key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, key_bytes, None)
        
        # Geçici Public Key'i serileştir
        ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Paket formatı: [Pub Key Uzunluğu (4 byte)] + [Pub Key] + [Nonce (12 byte)] + [Ciphertext]
        return len(ephemeral_pub_bytes).to_bytes(4, 'big') + ephemeral_pub_bytes + nonce + ciphertext

    def decrypt_key(self, encrypted_data, private_key):
        """ECC Private Key ile şifrelenmiş simetrik anahtarı çözer"""
        try:
            # Paketi ayrıştır
            pub_len = int.from_bytes(encrypted_data[:4], 'big')
            ephemeral_pub_bytes = encrypted_data[4:4+pub_len]
            nonce = encrypted_data[4+pub_len:4+pub_len+12]
            ciphertext = encrypted_data[4+pub_len+12:]
            
            # Geçici Public Key'i yükle
            ephemeral_public_key = serialization.load_pem_public_key(ephemeral_pub_bytes, backend=default_backend())
            
            # ECDH ile ortak sırrı hesapla (Kendi private key'imiz + Gelen ephemeral public key)
            shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)
            
            # Anahtar türetme (Aynı parametrelerle)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'ecc_handshake',
                backend=default_backend()
            ).derive(shared_key)
            
            # Deşifrele
            aesgcm = AESGCM(derived_key)
            original_key = aesgcm.decrypt(nonce, ciphertext, None)
            return original_key
        except Exception as e:
            raise ValueError(f"ECC Deşifreleme Hatası: {e}")