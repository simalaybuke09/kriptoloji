class RailFenceCipher:
    def encrypt(self, text, rails):
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

    def decrypt(self, text, rails):
        text = text.upper()
        rails = int(rails)
        if rails <= 1: return text
        n = len(text)
        rail_matrix = [['\n' for _ in range(n)] for _ in range(rails)]
        direction_down, row, col = False, 0, 0
        for i in range(n):
            if row == 0 or row == rails - 1: direction_down = not direction_down
            rail_matrix[row][col] = '*'; col += 1; row += 1 if direction_down else -1
        index = 0
        for i in range(rails):
            for j in range(n):
                if rail_matrix[i][j] == '*' and index < n: rail_matrix[i][j] = text[index]; index += 1
        result = []
        direction_down, row, col = False, 0, 0
        for i in range(n):
            if row == 0 or row == rails - 1: direction_down = not direction_down
            result.append(rail_matrix[row][col]); col += 1; row += 1 if direction_down else -1
        return "".join(result)