import hashlib

class CryptoFunctions:
    
    # --- YARDIMCI METOTLAR ---
    def _get_key_order(self, key):
        """Anahtar kelimedeki harflerin alfabetik sıra indekslerini döndürür."""
        sorted_chars = sorted(list(key.upper()))
        order = []
        key_list = list(key.upper())
        
        # Anahtar kelimenin her harfinin, sıralanmış listedeki ilk indeksini bulur
        for char in sorted_chars:
            # Aynı harfler varsa doğru indeksi bulmak için .pop kullanılır
            idx = key_list.index(char)
            order.append(idx)
            key_list[idx] = None # Kullanılan indeksi None yaparak bir sonraki aynı harfi atlamayı sağlar
        return order

    # --- COLUMNAR TRANSPOSITION CIPHER (YENİ EKLENDİ) ---
    def columnar_encrypt(self, text, key):
        """Columnar Transposition Cipher ile şifreleme"""
        text = text.replace(' ', '').upper()
        key = key.upper()
        cols = len(key)
        
        # Mesajı matrise doldur
        rows = (len(text) + cols - 1) // cols
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        idx = 0
        for i in range(rows):
            for j in range(cols):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
                else:
                    matrix[i][j] = '*' # Eksik yerleri doldur
        
        # Sütunları anahtar sırasına göre oku
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
        
        # Anahtar sırasını al ve ters çevir (şifreli metnin hangi sütuna ait olduğunu bulmak için)
        key_order = self._get_key_order(key)
        
        # Boş bir matris oluştur
        decryption_matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        # Şifreli metni sütun sütun doğru yerlere doldur
        char_index = 0
        
        for i, original_col_index in enumerate(key_order):
            for r in range(rows):
                if char_index < n:
                    decryption_matrix[r][original_col_index] = text[char_index]
                    char_index += 1
        
        # Deşifreli metni matrisi satır satır okuyarak oluştur
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
    
    # --- PLAYFAIR CIPHER ---
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
    
    # --- ROUTE CIPHER ---
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
    
    # --- RAIL FENCE CIPHER ---
    def rail_fence_encrypt(self, text, rails):
        """Rail Fence Cipher ile şifreleme (Encryption)"""
        text = ''.join(c for c in text.upper() if c.isalpha())
        rails = int(rails)

        if rails <= 1:
            return text

        rail_matrix = [['\n' for _ in range(len(text))] for _ in range(rails)]
        direction_down = False 
        row, col = 0, 0
        
        for char in text:
            if row == 0 or row == rails - 1:
                direction_down = not direction_down
            
            rail_matrix[row][col] = char
            col += 1
            
            if direction_down:
                row += 1
            else:
                row -= 1

        result = []
        for i in range(rails):
            for j in range(len(text)):
                if rail_matrix[i][j] != '\n':
                    result.append(rail_matrix[i][j])
                    
        return "".join(result)

    def rail_fence_decrypt(self, text, rails):
        """Rail Fence Cipher ile deşifreleme (Decryption)"""
        text = text.upper()
        rails = int(rails)

        if rails <= 1:
            return text

        n = len(text)
        rail_matrix = [['\n' for _ in range(n)] for _ in range(rails)]
        
        # 1. Matristeki yerleri işaretle
        direction_down = False
        row, col = 0, 0
        for i in range(n):
            if row == 0 or row == rails - 1:
                direction_down = not direction_down
            rail_matrix[row][col] = '*' 
            col += 1
            if direction_down:
                row += 1
            else:
                row -= 1

        # 2. İşaretli yerlere şifreli metni yerleştir
        index = 0
        for i in range(rails):
            for j in range(n):
                if rail_matrix[i][j] == '*' and index < n:
                    rail_matrix[i][j] = text[index]
                    index += 1

        # 3. Zikzak sırasına göre matrisi oku
        result = []
        direction_down = False
        row, col = 0, 0
        for i in range(n):
            if row == 0 or row == rails - 1:
                direction_down = not direction_down
            
            result.append(rail_matrix[row][col])
            col += 1
            
            if direction_down:
                row += 1
            else:
                row -= 1

        return "".join(result)
    def route_encrypt(self, text, key):
        """Route Cipher (Saat Yönü Spiral) ile şifreleme"""
        text = ''.join(c for c in text.upper() if c.isalpha())
        key = int(key) # Key burada matrisin yatay uzunluğudur (sütun sayısı)
        
        cols = key
        rows = (len(text) + cols - 1) // cols
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        # 1. Metni matrise satır satır doldur
        idx = 0
        for i in range(rows):
            for j in range(cols):
                if idx < len(text):
                    matrix[i][j] = text[idx]
                    idx += 1
                else:
                    matrix[i][j] = '*' # Görseldeki gibi dolgu karakteri

        # 2. Matrisi saat yönünde spiral olarak oku
        encrypted_text = []
        top, bottom, left, right = 0, rows - 1, 0, cols - 1

        while top <= bottom and left <= right:
            # Sağ üstten başla (Görselde B, U, G, İ, Z, L, İ, B, İ, R, M, E, S, A, J, D, İ, R yerleştirilmiş)
            # Okuma: Sağdan sola (Üst sıra)
            for i in range(right, left - 1, -1):
                encrypted_text.append(matrix[top][i])
            top += 1

            # Yukarıdan aşağıya (Sol sütun)
            for i in range(top, bottom + 1):
                encrypted_text.append(matrix[i][left])
            left += 1
            
            # Soldan sağa (Alt sıra)
            if top <= bottom:
                for i in range(left, right + 1):
                    encrypted_text.append(matrix[bottom][i])
                bottom -= 1

            # Aşağıdan yukarıya (Sağ sütun)
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    encrypted_text.append(matrix[i][right])
                right -= 1
        
        # Dolgu karakterini çıkararak sonucu döndür
        return "".join(c for c in encrypted_text if c != '*')

    def route_decrypt(self, text, key):
        """Route Cipher (Saat Yönü Spiral) ile deşifreleme"""
        text = text.upper()
        cols = int(key)
        n = len(text)
        rows = (n + cols - 1) // cols
        
        decryption_matrix = [['' for _ in range(cols)] for _ in range(rows)]
        
        # 1. Matristeki spiral rotanın pozisyonlarını işaretle
        path_matrix = [['\n' for _ in range(cols)] for _ in range(rows)]
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        spiral_order = []

        while top <= bottom and left <= right:
            # Sağdan sola (Üst sıra)
            for i in range(right, left - 1, -1):
                spiral_order.append((top, i))
            top += 1

            # Yukarıdan aşağıya (Sol sütun)
            for i in range(top, bottom + 1):
                spiral_order.append((i, left))
            left += 1
            
            # Soldan sağa (Alt sıra)
            if top <= bottom:
                for i in range(left, right + 1):
                    spiral_order.append((bottom, i))
                bottom -= 1

            # Aşağıdan yukarıya (Sağ sütun)
            if left <= right:
                for i in range(bottom, top - 1, -1):
                    spiral_order.append((i, right))
                right -= 1

        # 2. Şifreli metni spiral yörüngeye yerleştir
        for i, (r, c) in enumerate(spiral_order):
            if i < n:
                decryption_matrix[r][c] = text[i]

        # 3. Metni satır satır normal sırada oku
        decrypted_text = ""
        for i in range(rows):
            for j in range(cols):
                if decryption_matrix[i][j] != '*':
                    decrypted_text += decryption_matrix[i][j]
        
        return decrypted_text

    # --- HASHING ---
    def md5_hash(self, text):
        """MD5 hash oluştur"""
        return hashlib.md5(text.encode()).hexdigest()