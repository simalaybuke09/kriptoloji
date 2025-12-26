class VigenereCipher:
    def encrypt(self, text, key):
        result = ""
        key = key.upper()
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base + shift) % 26 + base)
                key_index += 1
            else: result += char
        return result
    
    def decrypt(self, text, key):
        result = ""
        key = key.upper()
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('A')
                base = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - base - shift) % 26 + base)
                key_index += 1
            else: result += char
        return result