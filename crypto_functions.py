import hashlib

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