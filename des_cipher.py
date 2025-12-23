from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class DESCipher:
    DES_INITIAL_PERMUTATION = list(range(63, -1, -1)) 
    DES_FINAL_PERMUTATION = [0] * 64
    for i, val in enumerate(DES_INITIAL_PERMUTATION):
        DES_FINAL_PERMUTATION[val] = i
        
    DES_SIMPLE_SBOX = [
        [0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x00],
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
    ]

    def _bytes_to_bits(self, data_bytes):
        bits = []
        for byte in data_bytes:
            bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        return bits

    def _bits_to_bytes(self, bits):
        data_bytes = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            data_bytes.append(byte)
        return data_bytes

    def _permute(self, bits, permutation_table):
        return [bits[i] for i in permutation_table]

    def _des_simple_feistel(self, R, subkey):
        R_list = list(R)
        subkey_bits = subkey[:32] 
        xor_result = [R_list[i] ^ subkey_bits[i] for i in range(32)]
        xor_result[4] = xor_result[4] ^ 1
        return xor_result

    def encrypt_manual(self, text, key_bytes):
        if len(key_bytes) != 8:
            raise ValueError("Manuel DES Anahtarı 8 byte (64 bit) olmalıdır.")
        
        block_size = 8
        text_bytes = text.encode('utf-8')
        padding_len = block_size - (len(text_bytes) % block_size)
        text_bytes += bytes([padding_len]) * padding_len
        
        encrypted_blocks = []
        key_bits = self._bytes_to_bits(list(key_bytes)) 
        
        for i in range(0, len(text_bytes), block_size):
            block = list(text_bytes[i:i + block_size])
            bits = self._bytes_to_bits(block)
            bits = self._permute(bits, self.DES_INITIAL_PERMUTATION)
            L = bits[:32]
            R = bits[32:]
            for round_num in range(2):
                L_prev = L
                subkey = key_bits[round_num*32 : (round_num*32)+32] if len(key_bits) >= 64 else key_bits[:32]
                R_next = [L_prev[j] ^ self._des_simple_feistel(R, subkey)[j] for j in range(32)]
                L = R
                R = R_next
            combined_bits = R + L
            final_bits = self._permute(combined_bits, self.DES_FINAL_PERMUTATION)
            encrypted_blocks.extend(self._bits_to_bytes(final_bits))
        
        return "".join(f'{b:02x}' for b in encrypted_blocks)

    def decrypt_manual(self, ciphertext_hex, key_bytes):
        if len(key_bytes) != 8:
            raise ValueError("Manuel DES Anahtarı 8 byte (64 bit) olmalıdır.")
        try:
            cipher_bytes = list(bytes.fromhex(ciphertext_hex))
        except ValueError:
            return "❌ Geçersiz Hex Kodu."
        block_size = 8
        if len(cipher_bytes) % block_size != 0:
            return "❌ Şifreli mesaj blok boyutuna (8B) uygun değil."

        decrypted_blocks = []
        key_bits = self._bytes_to_bits(list(key_bytes))

        for i in range(0, len(cipher_bytes), block_size):
            block = list(cipher_bytes[i:i + block_size])
            bits = self._bytes_to_bits(block)
            bits = self._permute(bits, self.DES_INITIAL_PERMUTATION)
            L = bits[:32]
            R = bits[32:]
            for round_num in range(1, -1, -1):
                R_prev = R
                subkey = key_bits[round_num*32 : (round_num*32)+32] if len(key_bits) >= 64 else key_bits[:32]
                L_new = R
                R_new = [L[j] ^ self._des_simple_feistel(R, subkey)[j] for j in range(32)]
                R = R_new
                L = L_new
            combined_bits = L + R
            final_bits = self._permute(combined_bits, self.DES_FINAL_PERMUTATION)
            decrypted_blocks.extend(self._bits_to_bytes(final_bits))
            
        padding_len = decrypted_blocks[-1]
        if 1 <= padding_len <= block_size:
            decrypted_blocks = decrypted_blocks[:-padding_len]
        
        try:
            decrypted_str = bytes(decrypted_blocks).decode('utf-8', errors='ignore')
            filtered_str = ''.join(c for c in decrypted_str if c.isalnum() or c in ' ')
            return filtered_str.strip()
        except:
            return f"❌ Deşifreleme Başarısız (Çıktı Hex): {''.join(f'{b:02x}' for b in decrypted_blocks)}"

    def encrypt_lib(self, plaintext, key_bytes, iv_bytes):
        if len(key_bytes) != 8: raise ValueError("DES Anahtarı 8 byte olmalıdır.")
        if len(iv_bytes) != 8: raise ValueError("DES IV 8 byte olmalıdır.")
        backend = default_backend()
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        return (encryptor.update(padded_data) + encryptor.finalize()).hex()

    def decrypt_lib(self, ciphertext_hex, key_bytes, iv_bytes):
        if len(key_bytes) != 8: raise ValueError("DES Anahtarı 8 byte olmalıdır.")
        if len(iv_bytes) != 8: raise ValueError("DES IV 8 byte olmalıdır.")
        ciphertext = bytes.fromhex(ciphertext_hex)
        backend = default_backend()
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        return (unpadder.update(decrypted_padded_data) + unpadder.finalize()).decode('utf-8')