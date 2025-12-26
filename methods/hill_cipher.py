import math

class HillCipher:
    def _egcd(self, a, b):
        if a == 0: return (b, 0, 1)
        else:
            g, y, x = self._egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def mod_inverse(self, a, m):
        g, x, y = self._egcd(a, m)
        if g != 1: raise ValueError(f"Hill Anahtarı İçin Hata: Determinant ({a}) ile 26 aralarında asal değil.")
        else: return x % m

    def _char_to_num(self, char): return ord(char.upper()) - ord('A')
    def _num_to_char(self, num): return chr(num % 26 + ord('A'))

    def _get_hill_matrix(self, key_str):
        try: k_flat = [int(i) for i in key_str.split(',')]
        except ValueError: raise ValueError("Hill Anahtarı sadece virgülle ayrılmış tam sayılardan oluşmalıdır!")
        N = len(k_flat)
        m = int(N**0.5)
        if m * m != N: raise ValueError(f"Hill Anahtarı Hata: {N} eleman kare matris oluşturamaz.")
        K = [[0] * m for _ in range(m)]
        for i in range(m):
            for j in range(m): K[i][j] = k_flat[i * m + j]
        return K, m
    
    def _get_minor(self, matrix, i, j):
        return [row[:j] + row[j+1:] for row in (matrix[:i] + matrix[i+1:])]

    def _get_determinant(self, matrix):
        n = len(matrix)
        if n == 0: return 1
        if n == 1: return matrix[0][0]
        if n == 2: return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
        det = 0
        for c in range(n):
            det += ((-1) ** c) * matrix[0][c] * self._get_determinant(self._get_minor(matrix, 0, c))
        return det

    def _get_matrix_inverse(self, matrix, modulus=26):
        n = len(matrix)
        det = self._get_determinant(matrix) % modulus
        if math.gcd(det, modulus) != 1: raise ValueError(f"Hill Anahtar Hata: Determinant ({det}) geçersiz.")
        det_inv = self.mod_inverse(det, modulus)
        cofactors = []
        for r in range(n):
            row = []
            for c in range(n):
                minor = self._get_minor(matrix, r, c)
                row.append(((-1) ** (r + c)) * self._get_determinant(minor))
            cofactors.append(row)
        inverse = [[0] * n for _ in range(n)]
        for r in range(n):
            for c in range(n): inverse[c][r] = (cofactors[r][c] * det_inv) % modulus
        return inverse

    def encrypt(self, text, key):
        text = ''.join(c for c in text.upper() if c.isalpha())
        K, m = self._get_hill_matrix(key)
        if len(text) % m != 0: text += 'X' * (m - (len(text) % m))
        det = self._get_determinant(K) % 26
        if math.gcd(det, 26) != 1: raise ValueError(f"Hill Anahtar Hata: Determinant ({det}) geçersiz.")
        cipher_text = ""
        for i in range(0, len(text), m):
            P = [self._char_to_num(text[i+j]) for j in range(m)]
            C = []
            for row in range(m):
                val = sum(K[row][col] * P[col] for col in range(m))
                C.append(val % 26)
            for num in C: cipher_text += self._num_to_char(num)
        return cipher_text

    def decrypt(self, text, key):
        text = text.upper()
        K, m = self._get_hill_matrix(key)
        K_inv = self._get_matrix_inverse(K, 26)
        plain_text = ""
        for i in range(0, len(text), m):
            C = [self._char_to_num(text[i+j]) for j in range(m)]
            P = []
            for row in range(m):
                val = sum(K_inv[row][col] * C[col] for col in range(m))
                P.append(val % 26)
            for num in P: plain_text += self._num_to_char(num)
        return plain_text