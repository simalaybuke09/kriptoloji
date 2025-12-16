import hashlib
import math
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class CryptoFunctions:
    
    def __init__(self):
        # Polybius Matrisi (İngilizce 5x5, I/J birleşik)
        self.POLYBIUS_SQUARE = {
            'A': (1, 1), 'B': (1, 2), 'C': (1, 3), 'D': (1, 4), 'E': (1, 5),
            'F': (2, 1), 'G': (2, 2), 'H': (2, 3), 'I': (2, 4), 'J': (2, 4),
            'K': (2, 5), 'L': (3, 1), 'M': (3, 2), 'N': (3, 3), 'O': (3, 4),
            'P': (3, 5), 'Q': (4, 1), 'R': (4, 2), 'S': (4, 3), 'T': (4, 4),
            'U': (4, 5), 'V': (5, 1), 'W': (5, 2), 'X': (5, 3), 'Y': (5, 4),
            'Z': (5, 5)
        }
        self.REVERSE_POLYBIUS_SQUARE = {
            (1, 1): 'A', (1, 2): 'B', (1, 3): 'C', (1, 4): 'D', (1, 5): 'E',
            (2, 1): 'F', (2, 2): 'G', (2, 3): 'H', (2, 4): 'I/J', (2, 5): 'K',
            (3, 1): 'L', (3, 2): 'M', (3, 3): 'N', (3, 4): 'O', (3, 5): 'P',
            (4, 1): 'Q', (4, 2): 'R', (4, 3): 'S', (4, 4): 'T', (4, 5): 'U',
            (5, 1): 'V', (5, 2): 'W', (5, 3): 'X', (5, 4): 'Y', (5, 5): 'Z'
        }
        
        # Pigpen Şifresi Haritaları (Kodlar Sembolleri Temsil Eder)
        self.PIGPEN_ENCRYPT_MAP = {
            'A': '□-R', 'B': '□-D', 'C': '□-L', 
            'D': '□-U', 'E': '□-UR', 'F': '□-UL',
            'G': '□-DR', 'H': '□-DL', 'I': '□-ALL',
            'J': 'X-R', 'K': 'X-D', 'L': 'X-L',
            'M': 'X-U', 'N': 'X-UR', 'O': 'X-UL',
            'P': 'X-DR', 'Q': 'X-DL', 'R': 'X-ALL',
            'S': '□-R.', 'T': '□-D.', 'U': '□-L.',
            'V': '□-U.', 'W': '□-UR.', 'X': '□-UL.',
            'Y': '□-DR.', 'Z': '□-DL.', ' ': ' '
        }
        self.PIGPEN_DECRYPT_MAP = {v: k for k, v in self.PIGPEN_ENCRYPT_MAP.items()}
# --- YARDIMCI METOTLAR (HILL) ---

    def _egcd(self, a, b):
        """Genişletilmiş Öklid Algoritması (GCD ve Modüler Tersi Bulmak İçin)"""
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self._egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def mod_inverse(self, a, m):
        """Modüler Ters (a^-1 mod m) hesaplar"""
        # Şart: gcd(a, m) ≡ 1 ise, a^-1 mod m vardır. [cite: 415]
        g, x, y = self._egcd(a, m)
        if g != 1:
            raise ValueError(f"Hill Anahtarı İçin Hata: Determinant ({a}) ile 26 aralarında asal değil. Geçersiz anahtar!")
        else:
            return x % m

    def _char_to_num(self, char):
        return ord(char.upper()) - ord('A')

    def _num_to_char(self, num):
        return chr(num % 26 + ord('A'))

    def _get_hill_matrix(self, key_str):
        """Anahtar dizesini kare matrise dönüştürür ve boyut kontrolü yapar."""
        try:
            k_flat = [int(i) for i in key_str.split(',')]
        except ValueError:
            raise ValueError("Hill Anahtarı sadece virgülle ayrılmış tam sayılardan oluşmalıdır!")

        N = len(k_flat)
        m = int(N**0.5) # Matris boyutu (m x m)

        # Şart 1: Kare Matris Kontrolü
        if m * m != N:
            raise ValueError(f"Hill Anahtarı Hata: Anahtar eleman sayısı ({N}), kare matris oluşturmaya uygun değil. Kare matris olmalıdır!")

        # Matrisi oluştur
        K = [[0] * m for _ in range(m)]
        for i in range(m):
            for j in range(m):
                K[i][j] = k_flat[i * m + j]
        
        return K, m
    
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
    
    # AES için Rijndael's MixColumns matrisi (Basitleştirilmiş)
    AES_MIX_COLUMNS = [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ]

    DES_INITIAL_PERMUTATION = list(range(63, -1, -1)) 
    
    # Ters İlk Permütasyon (InvP)
    DES_FINAL_PERMUTATION = [0] * 64
    for i, val in enumerate(DES_INITIAL_PERMUTATION):
        DES_FINAL_PERMUTATION[val] = i
        
    # Basit bir S-Box (Gerçek S-Box yerine sadece bir XOR operasyonu taklit edilecek)
    DES_SIMPLE_SBOX = [
        [0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07, 0x00],
        [0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
    ]

   

    def _aes_shift_rows(self, state):
        """Basitleştirilmiş ShiftRows işlemi (4x4 matris olarak düşünülür)."""
        # State: 16 baytlık düz liste
        s = [state[i:i+4] for i in range(0, 16, 4)] # 4x4 matrise dönüştür
        
        # 1. Satır: 0 kaydır
        # 2. Satır: 1 sola kaydır
        s[1] = s[1][1:] + s[1][:1]
        # 3. Satır: 2 sola kaydır
        s[2] = s[2][2:] + s[2][:2]
        # 4. Satır: 3 sola kaydır
        s[3] = s[3][3:] + s[3][:3]
        
        # Tekrar düz listeye dönüştür
        new_state = []
        for row in s:
            new_state.extend(row)
        return new_state

    def _aes_add_round_key(self, state, round_key):
        """State ve Anahtar arasında XOR işlemi."""
        return [state[i] ^ round_key[i] for i in range(16)]

    def _aes_galois_mul_2(self, byte):
        """Galois alanında x * byte (0x02 ile çarpma)."""
        res = byte << 1
        return res ^ 0x1b if res & 0x100 else res

    def _aes_inv_shift_rows(self, state):
        """Basitleştirilmiş Ters ShiftRows (InvShiftRows) işlemi."""
        # State: 16 baytlık düz liste
        s = [state[i:i+4] for i in range(0, 16, 4)] # 4x4 matrise dönüştür
        
        # 1. Satır: 0 kaydır (Aynı kalır)
        # 2. Satır: 1 sağa kaydır (ShiftRows'un tersi)
        s[1] = s[1][-1:] + s[1][:-1]
        # 3. Satır: 2 sağa kaydır
        s[2] = s[2][-2:] + s[2][:-2]
        # 4. Satır: 3 sağa kaydır
        s[3] = s[3][-3:] + s[3][:-3]
        
        # Tekrar düz listeye dönüştür
        new_state = []
        for row in s:
            new_state.extend(row)
        return new_state
    
    def _bytes_to_bits(self, data_bytes):
        """Bayt listesini bit listesine dönüştürür."""
        bits = []
        for byte in data_bytes:
            bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        return bits

    def _bits_to_bytes(self, bits):
        """Bit listesini bayt listesine dönüştürür."""
        data_bytes = []
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                byte = (byte << 1) | bits[i + j]
            data_bytes.append(byte)
        return data_bytes

    def _permute(self, bits, permutation_table):
        """Bit listesine P-Box uygular."""
        return [bits[i] for i in permutation_table]

    def _des_simple_feistel(self, R, subkey):
        """Basitleştirilmiş Feistel Fonksiyonu f(R, K_i)"""
        # 1. R'yi alt anahtar (subkey) ile XOR'la (Basitlik için subkey = R'nin 32 biti)
        R_list = list(R)
        
        # Subkey'i 32 bit olarak alalım (R'nin ilk yarısı)
        subkey_bits = subkey[:32] 
        
        # 2. XOR (32 bit)
        xor_result = [R_list[i] ^ subkey_bits[i] for i in range(32)]
        
        # 3. S-Box taklidi: Sadece 4. bitini ters çevirelim (Basit non-lineerlik)
        xor_result[4] = xor_result[4] ^ 1
        
        return xor_result
    
    # --- MANUEL AES CIPHER (BASİTLEŞTİRİLMİŞ) ---
    def aes_encrypt_manual(self, text, key_bytes):
        """AES-128'in basit şifrelemesi: Bloklama mantığı eklendi."""
        
        if len(key_bytes) != 16:
            raise ValueError("Manuel AES Anahtarı 16 byte (128 bit) olmalıdır.")
        
        text_bytes = text.encode('utf-8')
        
        # 16 baytlık dolgu ile toplam uzunluğu hesapla
        block_size = 16
        padding_len = block_size - (len(text_bytes) % block_size)
        
        # PKCS7 benzeri dolgu: dolgu uzunluğunu belirten baytlarla doldur
        text_bytes += bytes([padding_len]) * padding_len
        
        encrypted_blocks = []
        round_key = list(key_bytes) 
        
        # Tüm mesaj bloklar halinde işlenir
        for i in range(0, len(text_bytes), block_size):
            block = text_bytes[i:i + block_size]
            state = list(block)
            
            # Şifreleme Adımları (Aynı kalır)
            state = self._aes_add_round_key(state, round_key)
            for j in range(1):
                state = self._aes_shift_rows(state)
                state = self._aes_add_round_key(state, round_key)
            
            encrypted_blocks.extend(state)
        
        # Tüm şifreli baytları tek bir hex dizesi olarak döndür
        return "".join(f'{b:02x}' for b in encrypted_blocks)
    def aes_decrypt_manual(self, ciphertext_hex, key_bytes):
        """AES-128'in basit deşifrelemesi: Bloklama ve dolgu kaldırma mantığı eklendi."""
        
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
            
            # Deşifreleme Adımları (Aynı kalır)
            for j in range(1):
                state = self._aes_add_round_key(state, round_key)
                state = self._aes_inv_shift_rows(state)

            state = self._aes_add_round_key(state, round_key)
            decrypted_bytes.extend(state)
            
        # 1. Dolguyu Kaldır (Unpadding)
        if not decrypted_bytes:
            return ""
            
        padding_len = decrypted_bytes[-1]
        
        # Dolgu uzunluğu 1 ile 16 arasında ve son bayt dolgu uzunluğunu belirtiyorsa
        if 1 <= padding_len <= block_size:
            # Sadece dolgu karakterlerinin doğru olup olmadığını basitçe kontrol edelim
            if all(b == padding_len for b in decrypted_bytes[-padding_len:]):
                decrypted_bytes = decrypted_bytes[:-padding_len]
        
        # 2. String'e Çevir ve Filtrele (Önceki temizleme mantığı)
        try:
            decrypted_str = bytes(decrypted_bytes).decode('utf-8', errors='ignore')
            filtered_str = ''.join(c for c in decrypted_str if c.isalnum() or c in ' ')
            return filtered_str.strip()
        except:
            return f"❌ Deşifreleme Başarısız (Çıktı Hex): {''.join(f'{b:02x}' for b in decrypted_bytes)}"
        
        # --- MANUEL DES CIPHER (BASİTLEŞTİRİLMİŞ) ---
    def des_encrypt_manual(self, text, key_bytes):
        """Basitleştirilmiş Manuel DES şifrelemesi."""
        
        if len(key_bytes) != 8:
            raise ValueError("Manuel DES Anahtarı 8 byte (64 bit) olmalıdır.")
        
        block_size = 8
        text_bytes = text.encode('utf-8')
        padding_len = block_size - (len(text_bytes) % block_size)
        text_bytes += bytes([padding_len]) * padding_len
        
        encrypted_blocks = []
        
        # Anahtar Genişletme (Basitleştirilmiş: Sadece anahtarı bit olarak alalım)
        key_bits = self._bytes_to_bits(list(key_bytes)) 
        
        for i in range(0, len(text_bytes), block_size):
            block = list(text_bytes[i:i + block_size])
            bits = self._bytes_to_bits(block)
            
            # 1. İlk Permütasyon (IP)
            bits = self._permute(bits, self.DES_INITIAL_PERMUTATION)
            
            # 2. Blokları L0 ve R0 olarak ayır
            L = bits[:32] # 32 bit
            R = bits[32:] # 32 bit
            
            # 3. Feistel Döngüsü (2 Tur)
            for round_num in range(2):
                L_prev = L
                # Subkey Basitleştirme: Key'in yarısı
                subkey = key_bits[round_num*32 : (round_num*32)+32] if len(key_bits) >= 64 else key_bits[:32]
                
                # R_next = L_prev XOR f(R_prev, K_i)
                R_next = [L_prev[j] ^ self._des_simple_feistel(R, subkey)[j] for j in range(32)]
                
                # L_next = R_prev (Blok değişimi)
                L = R
                R = R_next
            
            # 4. Blokları birleştir ve Final Permütasyon (InvIP)
            combined_bits = R + L # Dikkat: R ve L'nin yeri değiştirildi (Son takas)
            final_bits = self._permute(combined_bits, self.DES_FINAL_PERMUTATION)
            
            encrypted_blocks.extend(self._bits_to_bytes(final_bits))
        
        return "".join(f'{b:02x}' for b in encrypted_blocks)

    def des_decrypt_manual(self, ciphertext_hex, key_bytes):
        """Basitleştirilmiş Manuel DES deşifrelemesi."""
        
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
            
            # 1. Final Permütasyon (IP)
            bits = self._permute(bits, self.DES_INITIAL_PERMUTATION)
            
            # 2. Blokları L0 ve R0 olarak ayır
            L = bits[:32]
            R = bits[32:]
            
            # 3. Ters Feistel Döngüsü (Subkey'ler tersten uygulanır)
            # 2 Tur için, subkey'ler tersten alınır.
            for round_num in range(1, -1, -1): # round_num: 1, 0
                R_prev = R
                # Subkey Basitleştirme: Key'in yarısı
                subkey = key_bits[round_num*32 : (round_num*32)+32] if len(key_bits) >= 64 else key_bits[:32]
                
                # R_prev = L_next (Ters Değişim)
                # L_prev = R_next XOR f(L_prev, K_i)
                
                # Yeni L = R_prev (Blok değişimi)
                L_new = R
                
                # Yeni R = L_prev XOR f(R_prev, K_i)
                R_new = [L[j] ^ self._des_simple_feistel(R, subkey)[j] for j in range(32)]
                
                R = R_new
                L = L_new

            # 4. Blokları birleştir ve Final Permütasyon (InvIP)
            combined_bits = L + R # Dikkat: L ve R'nin yeri değiştirildi (Son takasın tersi)
            final_bits = self._permute(combined_bits, self.DES_FINAL_PERMUTATION)
            
            decrypted_blocks.extend(self._bits_to_bytes(final_bits))
            
        # Dolgu Kaldırma (AES'tekiyle aynı mantıkta)
        padding_len = decrypted_blocks[-1]
        if 1 <= padding_len <= block_size:
            decrypted_blocks = decrypted_blocks[:-padding_len]
        
        try:
            decrypted_str = bytes(decrypted_blocks).decode('utf-8', errors='ignore')
            filtered_str = ''.join(c for c in decrypted_str if c.isalnum() or c in ' ')
            return filtered_str.strip()
        except:
            return f"❌ Deşifreleme Başarısız (Çıktı Hex): {''.join(f'{b:02x}' for b in decrypted_blocks)}"
    # --- HILL CIPHER (m x m MATRİS - Sadece m=2 tam desteklenir) ---
    def hill_encrypt(self, text, key):
        """Hill Cipher ile şifreleme"""
        text = ''.join(c for c in text.upper() if c.isalpha())
        K, m = self._get_hill_matrix(key)

        if m != 2:
            return f"❌ HATA: Hill Cipher, 2x2 dışındaki boyutlar için şifreleme fonksiyonu (matris çarpımı) içermemektedir (Boyut: {m}x{m})."

        # Metin dolgusu
        if len(text) % m != 0:
            text += 'X' * (m - (len(text) % m))
        
        # Determinant kontrolü: det(K) = ad - bc (Sadece 2x2 için)
        det = K[0][0] * K[1][1] - K[0][1] * K[1][0]
        det = det % 26
        
        # Şart 2: GCD kontrolü [cite: 380]
        if math.gcd(det, 26) != 1:
            raise ValueError(f"Hill Anahtar Hata: Determinant ({det}), 26 ile aralarında asal değil. Geçersiz anahtar!")

        # Şifreleme (m=2 için)
        cipher_text = ""
        for i in range(0, len(text), m):
            P = [self._char_to_num(text[i]), self._char_to_num(text[i+1])]
            
            C1 = (K[0][0] * P[0] + K[0][1] * P[1]) % 26
            C2 = (K[1][0] * P[0] + K[1][1] * P[1]) % 26
            
            cipher_text += self._num_to_char(C1) + self._num_to_char(C2)
        
        return cipher_text

    def hill_decrypt(self, text, key):
        """Hill Cipher ile deşifreleme"""
        text = text.upper()
        K, m = self._get_hill_matrix(key)

        if m != 2:
            return f"❌ HATA: Hill Cipher, 2x2 dışındaki boyutlar için deşifreleme fonksiyonu (ters matris) içermemektedir (Boyut: {m}x{m})."
            
        # 2x2 Ters Matris Hesaplama:
        det = K[0][0] * K[1][1] - K[0][1] * K[1][0]
        det_mod_26 = det % 26
        
        # Determinant Tersi
        try:
            det_inv = self.mod_inverse(det_mod_26, 26)
        except ValueError as e:
            raise e
        
        # Ters Matrisi (K^-1) Hesapla: K^-1 = det_inv * [[d, -b], [-c, a]] mod 26
        K_inv = [
            [(K[1][1] * det_inv) % 26, ((-K[0][1] % 26) * det_inv) % 26],
            [((-K[1][0] % 26) * det_inv) % 26, (K[0][0] * det_inv) % 26]
        ]

        # Deşifreleme (m=2 için)
        plain_text = ""
        for i in range(0, len(text), m):
            C = [self._char_to_num(text[i]), self._char_to_num(text[i+1])]
            
            P1 = (K_inv[0][0] * C[0] + K_inv[0][1] * C[1]) % 26
            P2 = (K_inv[1][0] * C[0] + K_inv[1][1] * C[1]) % 26
            
            plain_text += self._num_to_char(P1) + self._num_to_char(P2)
        
        return plain_text

    # --- PIGPEN CIPHER ---
    def pigpen_encrypt(self, text):
        """Pigpen Cipher ile şifreleme (Semboller yerine kodlar döndürülür)"""
        text = text.upper()
        encrypted_codes = []
        
        for char in text:
            if char in self.PIGPEN_ENCRYPT_MAP:
                encrypted_codes.append(self.PIGPEN_ENCRYPT_MAP[char])
            else:
                encrypted_codes.append(char)
        
        return " ".join(encrypted_codes)

    def pigpen_decrypt(self, text):
        """Pigpen Cipher ile deşifreleme"""
        codes = text.upper().split()
        decrypted_text = []
        
        for code in codes:
            if code in self.PIGPEN_DECRYPT_MAP:
                decrypted_text.append(self.PIGPEN_DECRYPT_MAP[code])
            else:
                decrypted_text.append(code)
                
        return "".join(decrypted_text)


    # --- POLYBIUS CIPHER ---
    def polybius_encrypt(self, text):
        """Polybius Cipher ile şifreleme (Anahtar gerekmez)"""
        text = ''.join(c for c in text.upper() if c.isalpha())
        encrypted_coords = []
        
        for char in text:
            if char == 'J':
                char = 'I'
            
            if char in self.POLYBIUS_SQUARE:
                row, col = self.POLYBIUS_SQUARE[char]
                encrypted_coords.append(f"{row}{col}")
        
        return "".join(encrypted_coords)

    def polybius_decrypt(self, text):
        """Polybius Cipher ile deşifreleme"""
        text = text.replace(' ', '')
        decrypted_text = []
        
        if len(text) % 2 != 0:
            raise ValueError("Deşifreleme için şifreli metin çift sayıda rakam içermelidir.")
            
        for i in range(0, len(text), 2):
            try:
                row = int(text[i])
                col = int(text[i+1])
            except ValueError:
                raise ValueError("Şifreli metin sadece rakamlardan oluşmalıdır.")
            
            coord = (row, col)
            if coord in self.REVERSE_POLYBIUS_SQUARE:
                decrypted_char = self.REVERSE_POLYBIUS_SQUARE[coord].split('/')[0]
                decrypted_text.append(decrypted_char)
            else:
                decrypted_text.append('?')
                
        return "".join(decrypted_text)


    # --- YARDIMCI METOTLAR (COLUMNAR) ---
    def _get_key_order(self, key):
        """Columnar için anahtar kelimedeki harflerin alfabetik sıra indekslerini döndürür."""
        sorted_chars = sorted(list(key.upper()))
        order = []
        key_list = list(key.upper())
        
        for char in sorted_chars:
            idx = key_list.index(char)
            order.append(idx)
            key_list[idx] = None 
        return order
    
    # --- COLUMNAR TRANSPOSITION CIPHER ---
    def columnar_encrypt(self, text, key):
        """Columnar Transposition Cipher ile şifreleme"""
        text = text.replace(' ', '').upper()
        cols = len(key)
        
        rows = (len(text) + cols - 1) // cols
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        idx = 0
        for i in range(rows):
            for j in range(cols):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
                else:
                    matrix[i][j] = '*' 
        
        key_order = self._get_key_order(key)
        encrypted_text = []
        
        for original_col_index in key_order:
            for i in range(rows):
                encrypted_text.append(matrix[i][original_col_index])
        
        return "".join(encrypted_text)

    def columnar_decrypt(self, text, key):
        """Columnar Transposition Cipher ile deşifreleme"""
        key = key.upper()
        cols = len(key)
        n = len(text)
        rows = (n + cols - 1) // cols
        
        key_order = self._get_key_order(key)
        decryption_matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        char_index = 0
        
        for i, original_col_index in enumerate(key_order):
            for r in range(rows):
                if char_index < n:
                    decryption_matrix[r][original_col_index] = text[char_index]
                    char_index += 1
        
        decrypted_text = ""
        for i in range(rows):
            for j in range(cols):
                if decryption_matrix[i][j] != '*':
                    decrypted_text += decryption_matrix[i][j]
        
        return decrypted_text
    
    # --- ROUTE CIPHER (SPIRAL - SAAT YÖNÜ) ---
    def route_encrypt(self, text, key):
        """Route Cipher (Saat Yönü Spiral) ile şifreleme"""
        text = ''.join(c for c in text.upper() if c.isalpha())
        key = int(key) 
        
        cols = key
        rows = (len(text) + cols - 1) // cols
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        idx = 0
        for i in range(rows):
            for j in range(cols):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
                else:
                    matrix[i][j] = '*' 

        encrypted_text = []
        top, bottom, left, right = 0, rows - 1, 0, cols - 1

        while top <= bottom and left <= right:
            for i in range(right, left - 1, -1):
                encrypted_text.append(matrix[top][i])
            top += 1

            for i in range(top, bottom + 1):
                encrypted_text.append(matrix[i][left])
            left += 1
            
            if top <= bottom:
                for i in range(left, right + 1):
                    encrypted_text.append(matrix[bottom][i])
                bottom -= 1

            if left <= right:
                for i in range(bottom, top - 1, -1):
                    encrypted_text.append(matrix[i][right])
                right -= 1
        
        return "".join(c for c in encrypted_text if c != '*')

    def route_decrypt(self, text, key):
        """Route Cipher (Saat Yönü Spiral) ile deşifreleme"""
        text = text.upper()
        cols = int(key)
        n = len(text)
        rows = (n + cols - 1) // cols
        
        decryption_matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        path_matrix = [['\n' for _ in range(cols)] for _ in range(rows)]
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        spiral_order = []

        while top <= bottom and left <= right:
            for i in range(right, left - 1, -1):
                spiral_order.append((top, i))
            top += 1

            for i in range(top, bottom + 1):
                spiral_order.append((i, left))
            left += 1
            
            if top <= bottom:
                for i in range(left, right + 1):
                    spiral_order.append((bottom, i))
                bottom -= 1

            if left <= right:
                for i in range(bottom, top - 1, -1):
                    spiral_order.append((i, right))
                right -= 1

        for i, (r, c) in enumerate(spiral_order):
            if i < n:
                decryption_matrix[r][c] = text[i]

        decrypted_text = ""
        for i in range(rows):
            for j in range(cols):
                if decryption_matrix[i][j] != '*':
                    decrypted_text += decryption_matrix[i][j]
        
        return decrypted_text
    
    # --- CAESAR CIPHER ---
    def caesar_encrypt(self, text, shift):
        """Caesar Cipher ile şifreleme"""
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        return result
    
    def caesar_decrypt(self, text, shift):
        """Caesar Cipher ile deşifreleme"""
        return self.caesar_encrypt(text, -shift)
    
    # --- SUBSTITUTION CIPHER ---
    def substitution_encrypt(self, text, key):
        """Substitution Cipher ile şifreleme"""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        key = key.upper()
        result = ""
        if len(key) != 26 or len(set(key)) != 26:
            raise ValueError("Anahtar 26 farklı harf içermelidir!")
        
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char = char.upper()
                idx = alphabet.index(char)
                encrypted_char = key[idx]
                result += encrypted_char if is_upper else encrypted_char.lower()
            else:
                result += char
        return result
    
    def substitution_decrypt(self, text, key):
        """Substitution Cipher ile deşifreleme"""
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        key = key.upper()
        result = ""
        if len(key) != 26 or len(set(key)) != 26:
            raise ValueError("Anahtar 26 farklı harf içermelidir!")
        
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char = char.upper()
                idx = key.index(char)
                decrypted_char = alphabet[idx]
                result += decrypted_char if is_upper else decrypted_char.lower()
            else:
                result += char
        return result
    
    # --- VIGENERE CIPHER ---
    def vigenere_encrypt(self, text, key):
        """Vigenere Cipher ile şifreleme"""
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
                key_index += 1
            else:
                result += char
        return result
    
    def vigenere_decrypt(self, text, key):
        """Vigenere Cipher ile deşifreleme"""
        result = ""
        key = key.upper()
        key_index = 0
        
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - shift) % 26 + base)
                key_index += 1
            else:
                result += char
        return result
    
    # --- PLAYFAIR CIPHER (Kısaltıldı) ---
    def playfair_encrypt(self, text, key):
        """Playfair Cipher ile şifreleme"""
        matrix = self._create_playfair_matrix(key)
        text = self._prepare_playfair_text(text)
        result = ""
        for i in range(0, len(text), 2):
            char1, char2 = text[i], text[i+1]
            row1, col1 = self._find_position(matrix, char1)
            row2, col2 = self._find_position(matrix, char2)
            if row1 == row2: result += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
            elif col1 == col2: result += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
            else: result += matrix[row1][col2] + matrix[row2][col1]
        return result
    
    def playfair_decrypt(self, text, key):
        """Playfair Cipher ile deşifreleme"""
        matrix = self._create_playfair_matrix(key)
        text = text.upper().replace('J', 'I')
        result = ""
        for i in range(0, len(text), 2):
            char1, char2 = text[i], text[i+1]
            row1, col1 = self._find_position(matrix, char1)
            row2, col2 = self._find_position(matrix, char2)
            if row1 == row2: result += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
            elif col1 == col2: result += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
            else: result += matrix[row1][col2] + matrix[row2][col1]
        return result
    
    def _create_playfair_matrix(self, key):
        """Playfair matrisi oluştur"""
        key = key.upper().replace('J', 'I')
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        matrix_str = ""
        for char in key:
            if char in alphabet and char not in matrix_str: matrix_str += char
        for char in alphabet:
            if char not in matrix_str: matrix_str += char
        return [list(matrix_str[i:i+5]) for i in range(0, 25, 5)]
    
    def _prepare_playfair_text(self, text):
        """Playfair için metni hazırla"""
        text = text.upper().replace('J', 'I').replace(' ', '')
        text = ''.join([c for c in text if c.isalpha()])
        result = ""
        i = 0
        while i < len(text):
            result += text[i]
            if i + 1 < len(text):
                if text[i] == text[i+1]:
                    result += 'X'
                else:
                    result += text[i+1]
                    i += 1
            else: result += 'X'
            i += 1
        return result
    
    def _find_position(self, matrix, char):
        """Matriste karakterin pozisyonunu bul"""
        for i, row in enumerate(matrix):
            if char in row: return i, row.index(char)
        return 0, 0
    
    # --- RAIL FENCE CIPHER (Kısaltıldı) ---
    def rail_fence_encrypt(self, text, rails):
        """Rail Fence Cipher ile şifreleme (Encryption)"""
        text = ''.join(c for c in text.upper() if c.isalpha())
        rails = int(rails)
        if rails <= 1: return text
        rail_matrix = [['\n' for _ in range(len(text))] for _ in range(rails)]
        direction_down, row, col = False, 0, 0
        for char in text:
            if row == 0 or row == rails - 1: direction_down = not direction_down
            rail_matrix[row][col] = char
            col += 1
            row += 1 if direction_down else -1
        result = []
        for i in range(rails):
            for j in range(len(text)):
                if rail_matrix[i][j] != '\n': result.append(rail_matrix[i][j])
        return "".join(result)

    def rail_fence_decrypt(self, text, rails):
        """Rail Fence Cipher ile deşifreleme (Decryption)"""
        text = text.upper()
        rails = int(rails)
        if rails <= 1: return text
        n = len(text)
        rail_matrix = [['\n' for _ in range(n)] for _ in range(rails)]
        direction_down, row, col = False, 0, 0
        for i in range(n):
            if row == 0 or row == rails - 1: direction_down = not direction_down
            rail_matrix[row][col] = '*' 
            col += 1
            row += 1 if direction_down else -1
        index = 0
        for i in range(rails):
            for j in range(n):
                if rail_matrix[i][j] == '*' and index < n:
                    rail_matrix[i][j] = text[index]
                    index += 1
        result = []
        direction_down, row, col = False, 0, 0
        for i in range(n):
            if row == 0 or row == rails - 1: direction_down = not direction_down
            result.append(rail_matrix[row][col])
            col += 1
            row += 1 if direction_down else -1
        return "".join(result)
    
    # --- HASHING ---
    def md5_hash(self, text):
        """MD5 hash oluştur"""
        return hashlib.md5(text.encode()).hexdigest()
    
    def aes_encrypt_lib(self, plaintext, key_bytes, iv_bytes):
        """AES-128 ile şifreleme (Kütüphaneli). CFB modu ve PKCS7 dolgusu kullanır."""
        
        if len(key_bytes) != 16:
            raise ValueError("AES Anahtarı 16 byte (128 bit) uzunluğunda olmalıdır.")
        if len(iv_bytes) != 16:
            raise ValueError("AES IV (Başlatma Vektörü) 16 byte uzunluğunda olmalıdır.")
            
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        encryptor = cipher.encryptor()

        # Dolgu (Padding) Uygula
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        # Şifreleme
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Şifreli veriyi kolay transfer için hex dizesine dönüştür
        return ciphertext.hex()

    def aes_decrypt_lib(self, ciphertext_hex, key_bytes, iv_bytes):
        """AES-128 ile deşifreleme (Kütüphaneli)."""

        if len(key_bytes) != 16:
            raise ValueError("AES Anahtarı 16 byte (128 bit) uzunluğunda olmalıdır.")
        if len(iv_bytes) != 16:
            raise ValueError("AES IV (Başlatma Vektörü) 16 byte uzunluğunda olmalıdır.")
            
        ciphertext = bytes.fromhex(ciphertext_hex)
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        decryptor = cipher.decryptor()
        
        # Deşifreleme
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Dolguyu Kaldır (Unpadding)
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return unpadded_data.decode('utf-8')
    
    # --- YENİ EKLENEN: KÜTÜPHANELİ DES ---
    
    def des_encrypt_lib(self, plaintext, key_bytes, iv_bytes):
        """DES ile şifreleme (Kütüphaneli). CFB modu ve PKCS7 dolgusu kullanır."""
        
        # DES için anahtar kontrolü (8 byte / 64 bit)
        if len(key_bytes) != 8:
            raise ValueError("DES Anahtarı 8 byte (64 bit) uzunluğunda olmalıdır.")
        # DES için IV kontrolü (8 byte / 64 bit)
        if len(iv_bytes) != 8:
            raise ValueError("DES IV (Başlatma Vektörü) 8 byte uzunluğunda olmalıdır.")
            
        backend = default_backend()
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        encryptor = cipher.encryptor()

        # Dolgu (Padding) Uygula (DES blok boyutu 64 bittir = 8 byte)
        padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
        padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()
        
        # Şifreleme
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Şifreli veriyi kolay transfer için hex dizesine dönüştür
        return ciphertext.hex()

    def des_decrypt_lib(self, ciphertext_hex, key_bytes, iv_bytes):
        """DES ile deşifreleme (Kütüphaneli)."""

        if len(key_bytes) != 8:
            raise ValueError("DES Anahtarı 8 byte (64 bit) uzunluğunda olmalıdır.")
        if len(iv_bytes) != 8:
            raise ValueError("DES IV (Başlatma Vektörü) 8 byte uzunluğunda olmalıdır.")
            
        ciphertext = bytes.fromhex(ciphertext_hex)
        backend = default_backend()
        cipher = Cipher(algorithms.TripleDES(key_bytes), modes.CFB(iv_bytes), backend=backend)
        decryptor = cipher.decryptor()
        
        # Deşifreleme
        decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Dolguyu Kaldır (Unpadding)
        unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        
        return unpadded_data.decode('utf-8')