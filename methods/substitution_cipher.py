class SubstitutionCipher:
    def encrypt(self, text, key):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        key = key.upper()
        result = ""
        if len(key) != 26 or len(set(key)) != 26: raise ValueError("Anahtar 26 farklı harf içermelidir!")
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char = char.upper()
                idx = alphabet.index(char)
                encrypted_char = key[idx]
                result += encrypted_char if is_upper else encrypted_char.lower()
            else: result += char
        return result
    
    def decrypt(self, text, key):
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        key = key.upper()
        result = ""
        if len(key) != 26 or len(set(key)) != 26: raise ValueError("Anahtar 26 farklı harf içermelidir!")
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                char = char.upper()
                idx = key.index(char)
                decrypted_char = alphabet[idx]
                result += decrypted_char if is_upper else decrypted_char.lower()
            else: result += char
        return result