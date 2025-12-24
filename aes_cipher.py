from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class AESCipher:
    def __init__(self):
        self.s_box = self._generate_sbox()
        self.inv_s_box = [0] * 256
        for i in range(256):
            self.inv_s_box[self.s_box[i]] = i

    def _rotl8(self, x, shift):
        return ((x << shift) | (x >> (8 - shift))) & 0xFF

    def _gf_mul(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1B
            b >>= 1
        return p

    def _gf_inv(self, a):
        if a == 0: return 0
        res = 1
        base = a
        exp = 254
        while exp > 0:
            if exp % 2 == 1:
                res = self._gf_mul(res, base)
            base = self._gf_mul(base, base)
            exp //= 2
        return res

    def _generate_sbox(self):
        sbox = [0] * 256
        for i in range(256):
            inv = self._gf_inv(i)
            s = inv ^ self._rotl8(inv, 1) ^ self._rotl8(inv, 2) ^ self._rotl8(inv, 3) ^ self._rotl8(inv, 4) ^ 0x63
            sbox[i] = s
        return sbox
    
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
    
    def _sub_bytes(self, state):
        return [self.s_box[b] for b in state]

    def _inv_sub_bytes(self, state):
        return [self.inv_s_box[b] for b in state]

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
                state = self._sub_bytes(state)
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
                state = self._inv_sub_bytes(state)
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