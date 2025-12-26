class DESManual:
    # Standard DES Constants
    IP_TABLE = [
        58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
    ]
    FP_TABLE = [
        40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
    ]
    E_TABLE = [
        32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
    ]
    P_TABLE = [
        16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
        2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
    ]
    PC1_TABLE = [
        57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
        59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
        31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
        29, 21, 13, 5, 28, 20, 12, 4
    ]
    PC2_TABLE = [
        14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
    ]
    SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    S_BOXES = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
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
                if i + j < len(bits):
                    byte = (byte << 1) | bits[i + j]
            data_bytes.append(byte)
        return data_bytes

    def _permute(self, bits, table):
        return [bits[i - 1] for i in table]

    def _generate_subkeys(self, key_bits):
        permuted_key = self._permute(key_bits, self.PC1_TABLE)
        C = permuted_key[:28]
        D = permuted_key[28:]
        subkeys = []
        for shift in self.SHIFTS:
            C = C[shift:] + C[:shift]
            D = D[shift:] + D[:shift]
            subkeys.append(self._permute(C + D, self.PC2_TABLE))
        return subkeys

    def _feistel_function(self, R, subkey):
        expanded_R = self._permute(R, self.E_TABLE)
        xored = [b ^ k for b, k in zip(expanded_R, subkey)]
        output_bits = []
        for i in range(8):
            chunk = xored[i*6 : (i+1)*6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            val = self.S_BOXES[i][row][col]
            output_bits.extend([(val >> j) & 1 for j in range(3, -1, -1)])
        return self._permute(output_bits, self.P_TABLE)

    def encrypt(self, text, key_bytes):
        if len(key_bytes) != 8: raise ValueError("Manuel DES Anahtarı 8 byte (64 bit) olmalıdır.")
        
        text_bytes = text.encode('utf-8')
        block_size = 8
        padding_len = block_size - (len(text_bytes) % block_size)
        text_bytes += bytes([padding_len]) * padding_len
        
        key_bits = self._bytes_to_bits(list(key_bytes))
        subkeys = self._generate_subkeys(key_bits)
        
        encrypted_blocks = []
        
        for i in range(0, len(text_bytes), block_size):
            block = list(text_bytes[i:i + block_size])
            bits = self._bytes_to_bits(block)
            
            bits = self._permute(bits, self.IP_TABLE)
            L = bits[:32]
            R = bits[32:]
            
            for round_num in range(16):
                L_prev = L
                R_prev = R
                L = R_prev
                f_result = self._feistel_function(R_prev, subkeys[round_num])
                R = [l ^ f for l, f in zip(L_prev, f_result)]
            
            combined_bits = R + L
            final_bits = self._permute(combined_bits, self.FP_TABLE)
            encrypted_blocks.extend(self._bits_to_bytes(final_bits))
            
        return "".join(f'{b:02x}' for b in encrypted_blocks)

    def decrypt(self, ciphertext_hex, key_bytes):
        if len(key_bytes) != 8: raise ValueError("Manuel DES Anahtarı 8 byte (64 bit) olmalıdır.")
        try: cipher_bytes = list(bytes.fromhex(ciphertext_hex))
        except ValueError: return "❌ Geçersiz Hex Kodu."
        
        block_size = 8
        if len(cipher_bytes) % block_size != 0: return "❌ Şifreli mesaj blok boyutuna (8B) uygun değil."
        
        key_bits = self._bytes_to_bits(list(key_bytes))
        subkeys = self._generate_subkeys(key_bits)[::-1]
        
        decrypted_blocks = []
        
        for i in range(0, len(cipher_bytes), block_size):
            block = list(cipher_bytes[i:i + block_size])
            bits = self._bytes_to_bits(block)
            
            bits = self._permute(bits, self.IP_TABLE)
            L = bits[:32]
            R = bits[32:]
            
            for round_num in range(16):
                L_prev = L
                R_prev = R
                L = R_prev
                f_result = self._feistel_function(R_prev, subkeys[round_num])
                R = [l ^ f for l, f in zip(L_prev, f_result)]
            
            combined_bits = L + R
            final_bits = self._permute(combined_bits, self.FP_TABLE)
            decrypted_blocks.extend(self._bits_to_bytes(final_bits))
            
        if not decrypted_blocks: return ""
        padding_len = decrypted_blocks[-1]
        if 1 <= padding_len <= block_size:
            is_valid = True
            for k in range(padding_len):
                if decrypted_blocks[-(k+1)] != padding_len:
                    is_valid = False
                    break
            if is_valid:
                decrypted_blocks = decrypted_blocks[:-padding_len]
        
        try:
            return bytes(decrypted_blocks).decode('utf-8')
        except: return f"❌ Deşifreleme Başarısız (Çıktı Hex): {''.join(f'{b:02x}' for b in decrypted_blocks)}"