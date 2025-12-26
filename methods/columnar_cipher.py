class ColumnarCipher:
    def _get_key_order(self, key):
        sorted_chars = sorted(list(key.upper()))
        order = []
        key_list = list(key.upper())
        for char in sorted_chars:
            idx = key_list.index(char)
            order.append(idx)
            key_list[idx] = None 
        return order
    
    def encrypt(self, text, key):
        text = text.replace(' ', '').upper()
        cols = len(key)
        rows = (len(text) + cols - 1) // cols
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        idx = 0
        for i in range(rows):
            for j in range(cols):
                if idx < len(text): matrix[i][j] = text[idx]; idx += 1
                else: matrix[i][j] = '*' 
        key_order = self._get_key_order(key)
        encrypted_text = []
        for original_col_index in key_order:
            for i in range(rows): encrypted_text.append(matrix[i][original_col_index])
        return "".join(encrypted_text)

    def decrypt(self, text, key):
        key = key.upper()
        cols = len(key)
        n = len(text)
        rows = (n + cols - 1) // cols
        key_order = self._get_key_order(key)
        decryption_matrix = [['' for _ in range(cols)] for _ in range(rows)]
        char_index = 0
        for i, original_col_index in enumerate(key_order):
            for r in range(rows):
                if char_index < n: decryption_matrix[r][original_col_index] = text[char_index]; char_index += 1
        decrypted_text = ""
        for i in range(rows):
            for j in range(cols):
                if decryption_matrix[i][j] != '*': decrypted_text += decryption_matrix[i][j]
        return decrypted_text