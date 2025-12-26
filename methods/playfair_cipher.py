class PlayfairCipher:
    def _create_playfair_matrix(self, key):
        key = key.upper().replace('J', 'I')
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        matrix_str = ""
        for char in key:
            if char in alphabet and char not in matrix_str: matrix_str += char
        for char in alphabet:
            if char not in matrix_str: matrix_str += char
        return [list(matrix_str[i:i+5]) for i in range(0, 25, 5)]
    
    def _prepare_playfair_text(self, text):
        text = text.upper().replace('J', 'I').replace(' ', '')
        text = ''.join([c for c in text if c.isalpha()])
        result = ""
        i = 0
        while i < len(text):
            result += text[i]
            if i + 1 < len(text):
                if text[i] == text[i+1]: result += 'X'
                else: result += text[i+1]; i += 1
            else: result += 'X'
            i += 1
        return result
    
    def _find_position(self, matrix, char):
        for i, row in enumerate(matrix):
            if char in row: return i, row.index(char)
        return 0, 0

    def encrypt(self, text, key):
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
    
    def decrypt(self, text, key):
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