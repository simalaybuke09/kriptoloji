import hashlib

class CryptoFunctions:
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
    
    def playfair_encrypt(self, text, key):
        """Playfair Cipher ile şifreleme"""
        # Playfair matrisi oluştur
        matrix = self._create_playfair_matrix(key)
        text = self._prepare_playfair_text(text)
        result = ""
        
        for i in range(0, len(text), 2):
            char1, char2 = text[i], text[i+1]
            row1, col1 = self._find_position(matrix, char1)
            row2, col2 = self._find_position(matrix, char2)
            
            if row1 == row2:  # Aynı satır
                result += matrix[row1][(col1 + 1) % 5]
                result += matrix[row2][(col2 + 1) % 5]
            elif col1 == col2:  # Aynı sütun
                result += matrix[(row1 + 1) % 5][col1]
                result += matrix[(row2 + 1) % 5][col2]
            else:  # Dikdörtgen
                result += matrix[row1][col2]
                result += matrix[row2][col1]
        
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
            
            if row1 == row2:  # Aynı satır
                result += matrix[row1][(col1 - 1) % 5]
                result += matrix[row2][(col2 - 1) % 5]
            elif col1 == col2:  # Aynı sütun
                result += matrix[(row1 - 1) % 5][col1]
                result += matrix[(row2 - 1) % 5][col2]
            else:  # Dikdörtgen
                result += matrix[row1][col2]
                result += matrix[row2][col1]
        
        return result
    
    def _create_playfair_matrix(self, key):
        """Playfair matrisi oluştur"""
        key = key.upper().replace('J', 'I')
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        matrix_str = ""
        
        for char in key:
            if char in alphabet and char not in matrix_str:
                matrix_str += char
        
        for char in alphabet:
            if char not in matrix_str:
                matrix_str += char
        
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
            else:
                result += 'X'
            i += 1
        
        return result
    
    def _find_position(self, matrix, char):
        """Matriste karakterin pozisyonunu bul"""
        for i, row in enumerate(matrix):
            if char in row:
                return i, row.index(char)
        return 0, 0
    
    def route_encrypt(self, text, key):
        """Route Cipher ile şifreleme"""
        key = int(key)
        text = text.replace(' ', '')
        
        # Matris oluştur
        rows = (len(text) + key - 1) // key
        matrix = [['' for _ in range(key)] for _ in range(rows)]
        
        idx = 0
        for i in range(rows):
            for j in range(key):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
        
        # Sütunları oku
        result = ""
        for j in range(key):
            for i in range(rows):
                if matrix[i][j]:
                    result += matrix[i][j]
        
        return result
    
    def route_decrypt(self, text, key):
        """Route Cipher ile deşifreleme"""
        key = int(key)
        rows = (len(text) + key - 1) // key
        matrix = [['' for _ in range(key)] for _ in range(rows)]
        
        idx = 0
        for j in range(key):
            for i in range(rows):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
        
        # Satırları oku
        result = ""
        for i in range(rows):
            for j in range(key):
                if matrix[i][j]:
                    result += matrix[i][j]
        
        return result
    
    def md5_hash(self, text):
        """MD5 hash oluştur"""
        return hashlib.md5(text.encode()).hexdigest()