class AffineCipher:
    def _gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def _mod_inverse(self, a, m):
        if self._gcd(a, m) != 1:
            return None
        for i in range(1, m):
            if (a * i) % m == 1:
                return i
        return None

    def encrypt(self, text, key):
        # Key format: "a,b" (Örn: 5,8)
        try:
            parts = key.split(',')
            if len(parts) != 2: raise ValueError
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            raise ValueError("Affine anahtarı 'a,b' formatında olmalıdır (örn: 5,8)")

        if self._gcd(a, 26) != 1:
            raise ValueError(f"a={a} değeri 26 ile aralarında asal olmalıdır!")
        
        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                x = ord(char) - base
                encrypted = (a * x + b) % 26
                result += chr(encrypted + base)
            else:
                result += char
        return result

    def decrypt(self, text, key):
        try:
            parts = key.split(',')
            if len(parts) != 2: raise ValueError
            a, b = int(parts[0]), int(parts[1])
        except ValueError:
            raise ValueError("Affine anahtarı 'a,b' formatında olmalıdır (örn: 5,8)")

        if self._gcd(a, 26) != 1:
            raise ValueError(f"a={a} değeri 26 ile aralarında asal olmalıdır!")
        
        a_inv = self._mod_inverse(a, 26)
        if a_inv is None:
             raise ValueError(f"a={a} için modüler ters bulunamadı.")

        result = ""
        for char in text:
            if char.isalpha():
                base = ord('A') if char.isupper() else ord('a')
                y = ord(char) - base
                decrypted = (a_inv * (y - b)) % 26
                result += chr(decrypted + base)
            else:
                result += char
        return result