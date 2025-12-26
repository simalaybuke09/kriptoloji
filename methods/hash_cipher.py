import hashlib

class HashCipher:
    def md5_hash(self, text):
        return hashlib.md5(text.encode()).hexdigest()