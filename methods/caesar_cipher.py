class CaesarCipher:
    def encrypt(self, text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
            else:
                result += char
        return result
    
    def decrypt(self, text, shift):
        return self.encrypt(text, -shift)