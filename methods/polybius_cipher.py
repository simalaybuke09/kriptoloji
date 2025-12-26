class PolybiusCipher:
    def __init__(self):
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

    def encrypt(self, text):
        text = ''.join(c for c in text.upper() if c.isalpha())
        encrypted_coords = []
        for char in text:
            if char == 'J': char = 'I'
            if char in self.POLYBIUS_SQUARE:
                row, col = self.POLYBIUS_SQUARE[char]
                encrypted_coords.append(f"{row}{col}")
        return "".join(encrypted_coords)

    def decrypt(self, text):
        text = text.replace(' ', '')
        decrypted_text = []
        if len(text) % 2 != 0: raise ValueError("Deşifreleme için şifreli metin çift sayıda rakam içermelidir.")
        for i in range(0, len(text), 2):
            try: row, col = int(text[i]), int(text[i+1])
            except ValueError: raise ValueError("Şifreli metin sadece rakamlardan oluşmalıdır.")
            coord = (row, col)
            decrypted_text.append(self.REVERSE_POLYBIUS_SQUARE.get(coord, '?').split('/')[0])
        return "".join(decrypted_text)