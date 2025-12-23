from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class AESCipher:
    AES_S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xae, 0x28, 0x5e, 0xa7, 0x64, 0x5c, 0x3e, 0x8a, 0x79, 0xea, 0xb5, 0x00, 0xba, 0x1e, 0x43,
        0x0a, 0x5d, 0x3a, 0x13, 0x1f, 0x4f, 0x8c, 0x82, 0x5f, 0x89, 0xa1, 0xb4, 0x87, 0xe9, 0xdb, 0x10,
        0x02, 0x03, 0x08, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x14, 0x16, 0x17, 0x19, 0x1c, 0x1d, 0x21, 0x22,
    ]
    
    AES_MIX_COLUMNS = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]

    def _aes_shift_rows(self, state):
        s = [state[i:i+4] for i in range(0, 16, 4)]
        s[1] = s[1][1:] + s[1][:1]
        s[2] = s[2][2:] + s[2][:2]
        s[3] = s[3][3:] + s[3][:3]
        new_state = []
        for row in s:
            new_state.extend(row)
        return new_state

    def _aes_add_round_key(self, state, round_key):
        return [state[i] ^ round_key[i] for i in range(16)]

    def _aes_inv_shift_rows(self, state):
        s = [state[i:i+4] for i in range(0, 16, 4)]
        s[1] = s[1][-1:] + s[1][:-1]
        s[2] = s[2][-2:] + s[2][:-2]
        s[3] = s[3][-3:] + s[3][:-3]
        new_state = []
        for row in s:
            new_state.extend(row)
        return new_state

    def encrypt_manual(self, text, key_bytes):
        if len(key_bytes) != 16:
            raise ValueError("Manuel AES Anahtarı 16 byte (128 bit) olmalıdır.")
        
        text_bytes = text.encode('utf-8')
        block_size = 16
        padding_len = block_size - (len(text_bytes) % block_size)
        text_bytes += bytes([padding_len]) * padding_len
        
        encrypted_blocks = []
        round_key = list(key_bytes) 
        
        for i in range(0, len(text_bytes), block_size):
            block = text_bytes[i:i + block_size]
            state = list(block)
            state = self._aes_add_round_key(state, round_key)
            for j in range(1):
                state = self._aes_shift_rows(state)
                state = self._aes_add_round_key(state, round_key)
            encrypted_blocks.extend(state)
        
        return "".join(f'{b:02x}' for b in encrypted_blocks)

    def decrypt_manual(self, ciphertext_hex, key_bytes):
        if len(key_bytes) != 16:
            raise ValueError("Manuel AES Anahtarı 16 byte (128 bit) olmalıdır.")
        
        try:
            cipher_bytes = list(bytes.fromhex(ciphertext_hex))
        except ValueError:
            return "❌ Geçersiz Hex Kodu."
            
        block_size = 16
        if len(cipher_bytes) % block_size != 0:
            return "❌ Şifreli mesaj blok boyutuna (16B) uygun değil."
            
        decrypted_bytes = []
        round_key = list(key_bytes) 

        for i in range(0, len(cipher_bytes), block_size):
            state = cipher_bytes[i:i + block_size]
            for j in range(1):
                state = self._aes_add_round_key(state, round_key)
                state = self._aes_inv_shift_rows(state)
            state = self._aes_add_round_key(state, round_key)
            decrypted_bytes.extend(state)
            
        if not decrypted_bytes:
            return ""
        padding_len = decrypted_bytes[-1]
        if 1 <= padding_len <= block_size:
            if all(b == padding_len for b in decrypted_bytes[-padding_len:]):
                decrypted_bytes = decrypted_bytes[:-padding_len]
        
        try:
            decrypted_str = bytes(decrypted_bytes).decode('utf-8', errors='ignore')
            filtered_str = ''.join(c for c in decrypted_str if c.isalnum() or c in ' ')
            return filtered_str.strip()
        except:
            return f"❌ Deşifreleme Başarısız (Çıktı Hex): {''.join(f'{b:02x}' for b in decrypted_bytes)}"

    def encrypt_lib(self, plaintext, key_bytes, iv_bytes):
        if len(key_bytes) != 16: raise ValueError("AES Anahtarı 16 byte olmalıdır.")
        if len(iv_bytes) != 16: raise ValueError("AES IV 16 byte olmalıdır.")
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        return (encryptor.update(padded_data) + encryptor.finalize()).hex()

    def decrypt_lib(self, ciphertext_hex, key_bytes, iv_bytes):
        if len(key_bytes) != 16: raise ValueError("AES Anahtarı 16 byte olmalıdır.")
        if len(iv_bytes) != 16: raise ValueError("AES IV 16 byte olmalıdır.")
        ciphertext = bytes.fromhex(ciphertext_hex)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return (unpadder.update(decrypted_padded_data) + unpadder.finalize()).decode('utf-8')