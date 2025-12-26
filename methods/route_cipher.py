class RouteCipher:
    def encrypt(self, text, key):
        text = ''.join(c for c in text.upper() if c.isalpha())
        key = int(key) 
        cols = key
        rows = (len(text) + cols - 1) // cols
        matrix = [['' for _ in range(cols)] for _ in range(rows)]
        idx = 0
        for i in range(rows):
            for j in range(cols):
                if idx < len(text): matrix[i][j] = text[idx]; idx += 1
                else: matrix[i][j] = '*' 
        encrypted_text = []
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        while top <= bottom and left <= right:
            for i in range(right, left - 1, -1): encrypted_text.append(matrix[top][i])
            top += 1
            for i in range(top, bottom + 1): encrypted_text.append(matrix[i][left])
            left += 1
            if top <= bottom:
                for i in range(left, right + 1): encrypted_text.append(matrix[bottom][i])
                bottom -= 1
            if left <= right:
                for i in range(bottom, top - 1, -1): encrypted_text.append(matrix[i][right])
                right -= 1
        return "".join(c for c in encrypted_text if c != '*')

    def decrypt(self, text, key):
        text = text.upper()
        cols = int(key)
        n = len(text)
        rows = (n + cols - 1) // cols
        decryption_matrix = [['' for _ in range(cols)] for _ in range(rows)]
        top, bottom, left, right = 0, rows - 1, 0, cols - 1
        spiral_order = []
        while top <= bottom and left <= right:
            for i in range(right, left - 1, -1): spiral_order.append((top, i))
            top += 1
            for i in range(top, bottom + 1): spiral_order.append((i, left))
            left += 1
            if top <= bottom:
                for i in range(left, right + 1): spiral_order.append((bottom, i))
                bottom -= 1
            if left <= right:
                for i in range(bottom, top - 1, -1): spiral_order.append((i, right))
                right -= 1
        for i, (r, c) in enumerate(spiral_order):
            if i < n: decryption_matrix[r][c] = text[i]
        decrypted_text = ""
        for i in range(rows):
            for j in range(cols):
                if decryption_matrix[i][j] != '*': decrypted_text += decryption_matrix[i][j]
        return decrypted_text