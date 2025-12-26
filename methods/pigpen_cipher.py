class PigpenCipher:
    def __init__(self):
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

    def encrypt(self, text):
        text = text.upper()
        encrypted_codes = []
        for char in text:
            if char in self.PIGPEN_ENCRYPT_MAP:
                encrypted_codes.append(self.PIGPEN_ENCRYPT_MAP[char])
            else:
                encrypted_codes.append(char)
        return " ".join(encrypted_codes)

    def decrypt(self, text):
        codes = text.upper().split()
        decrypted_text = []
        for code in codes:
            decrypted_text.append(self.PIGPEN_DECRYPT_MAP.get(code, code))
        return "".join(decrypted_text)