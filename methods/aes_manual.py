class AESManual:
    RCON = [
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00
    ]

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
    
    def _key_expansion(self, key):
        w = [0] * 44
        for i in range(4):
            w[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2] << 8) | key[4*i+3]
        
        for i in range(4, 44):
            temp = w[i-1]
            if i % 4 == 0:
                temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
                temp = (self.s_box[(temp >> 24) & 0xFF] << 24) | \
                       (self.s_box[(temp >> 16) & 0xFF] << 16) | \
                       (self.s_box[(temp >> 8) & 0xFF] << 8) | \
                       (self.s_box[temp & 0xFF])
                temp ^= (self.RCON[i // 4] << 24)
            w[i] = w[i-4] ^ temp
            
        round_keys = []
        for i in range(44):
            round_keys.append((w[i] >> 24) & 0xFF)
            round_keys.append((w[i] >> 16) & 0xFF)
            round_keys.append((w[i] >> 8) & 0xFF)
            round_keys.append(w[i] & 0xFF)
        return round_keys

    def _aes_shift_rows(self, state):
        s = [state[i:i+4] for i in range(0, 16, 4)]
        s[1] = s[1][1:] + s[1][:1]
        s[2] = s[2][2:] + s[2][:2]
        s[3] = s[3][3:] + s[3][:3]
        new_state = []
        for row in s:
            new_state.extend(row)
        return new_state

    def _inv_shift_rows(self, state):
        s = [state[i:i+4] for i in range(0, 16, 4)]
        s[1] = s[1][-1:] + s[1][:-1]
        s[2] = s[2][-2:] + s[2][:-2]
        s[3] = s[3][-3:] + s[3][:-3]
        new_state = []
        for row in s: new_state.extend(row)
        return new_state
    
    def _sub_bytes(self, state):
        return [self.s_box[b] for b in state]

    def _inv_sub_bytes(self, state):
        return [self.inv_s_box[b] for b in state]

    def _aes_add_round_key(self, state, round_key):
        return [state[i] ^ round_key[i] for i in range(16)]

    def _mix_columns(self, state):
        new_state = [0] * 16
        for c in range(4):
            # Note: Using row-major indexing based on previous shift_rows logic
            # Column c consists of indices c, c+4, c+8, c+12
            s0, s1, s2, s3 = state[c], state[c+4], state[c+8], state[c+12]
            new_state[c]    = self._gf_mul(0x02, s0) ^ self._gf_mul(0x03, s1) ^ s2 ^ s3
            new_state[c+4]  = s0 ^ self._gf_mul(0x02, s1) ^ self._gf_mul(0x03, s2) ^ s3
            new_state[c+8]  = s0 ^ s1 ^ self._gf_mul(0x02, s2) ^ self._gf_mul(0x03, s3)
            new_state[c+12] = self._gf_mul(0x03, s0) ^ s1 ^ s2 ^ self._gf_mul(0x02, s3)
        return new_state

    def _inv_mix_columns(self, state):
        new_state = [0] * 16
        for c in range(4):
            s0, s1, s2, s3 = state[c], state[c+4], state[c+8], state[c+12]
            new_state[c]    = self._gf_mul(0x0e, s0) ^ self._gf_mul(0x0b, s1) ^ self._gf_mul(0x0d, s2) ^ self._gf_mul(0x09, s3)
            new_state[c+4]  = self._gf_mul(0x09, s0) ^ self._gf_mul(0x0e, s1) ^ self._gf_mul(0x0b, s2) ^ self._gf_mul(0x0d, s3)
            new_state[c+8]  = self._gf_mul(0x0d, s0) ^ self._gf_mul(0x09, s1) ^ self._gf_mul(0x0e, s2) ^ self._gf_mul(0x0b, s3)
            new_state[c+12] = self._gf_mul(0x0b, s0) ^ self._gf_mul(0x0d, s1) ^ self._gf_mul(0x09, s2) ^ self._gf_mul(0x0e, s3)
        return new_state

    def encrypt(self, text, key_bytes):
        if len(key_bytes) != 16: raise ValueError("Manuel AES Anahtarı 16 byte (128 bit) olmalıdır.")
        
        text_bytes = text.encode('utf-8')
        block_size = 16
        padding_len = block_size - (len(text_bytes) % block_size)
        text_bytes += bytes([padding_len]) * padding_len
        
        round_keys = self._key_expansion(list(key_bytes))
        encrypted_blocks = []
        
        for i in range(0, len(text_bytes), block_size):
            state = list(text_bytes[i:i + block_size])
            state = self._aes_add_round_key(state, round_keys[0:16])
            
            for r in range(1, 10):
                state = self._sub_bytes(state)
                state = self._aes_shift_rows(state)
                state = self._mix_columns(state)
                state = self._aes_add_round_key(state, round_keys[r*16 : (r+1)*16])
            
            state = self._sub_bytes(state)
            state = self._aes_shift_rows(state)
            state = self._aes_add_round_key(state, round_keys[160:176])
            
            encrypted_blocks.extend(state)
        return "".join(f'{b:02x}' for b in encrypted_blocks)

    def decrypt(self, ciphertext_hex, key_bytes):
        if len(key_bytes) != 16: raise ValueError("Manuel AES Anahtarı 16 byte (128 bit) olmalıdır.")
        try: cipher_bytes = list(bytes.fromhex(ciphertext_hex))
        except ValueError: return "❌ Geçersiz Hex Kodu."
        
        block_size = 16
        if len(cipher_bytes) % block_size != 0: return "❌ Şifreli mesaj blok boyutuna (16B) uygun değil."
        
        round_keys = self._key_expansion(list(key_bytes))
        decrypted_bytes = []
        
        for i in range(0, len(cipher_bytes), block_size):
            state = list(cipher_bytes[i:i + block_size])
            state = self._aes_add_round_key(state, round_keys[160:176])
            
            for r in range(9, 0, -1):
                state = self._inv_shift_rows(state)
                state = self._inv_sub_bytes(state)
                state = self._aes_add_round_key(state, round_keys[r*16 : (r+1)*16])
                state = self._inv_mix_columns(state)
            
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._aes_add_round_key(state, round_keys[0:16])
            
            decrypted_bytes.extend(state)
            
        if not decrypted_bytes: return ""
        padding_len = decrypted_bytes[-1]
        if 1 <= padding_len <= block_size:
            is_valid = True
            for k in range(padding_len):
                if decrypted_bytes[-(k+1)] != padding_len:
                    is_valid = False
                    break
            if is_valid:
                decrypted_bytes = decrypted_bytes[:-padding_len]
        
        try:
            return bytes(decrypted_bytes).decode('utf-8')
        except: return f"❌ Deşifreleme Başarısız (Çıktı Hex): {''.join(f'{b:02x}' for b in decrypted_bytes)}"