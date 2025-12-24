import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import json
from datetime import datetime
from crypto_functions import CryptoFunctions
from aes_cipher import AESCipher
from des_cipher import DESCipher
from rsa_cipher import RSACipher
from ecc_cipher import ECCCipher
import os

class ClientApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🔒 İstemci - Şifreleme Servisi")
        self.window.geometry("800x750")
        self.window.configure(bg="#f0f0f0")
        
        self.crypto = CryptoFunctions()
        self.aes = AESCipher()
        self.des = DESCipher()
        self.rsa = RSACipher()
        self.ecc = ECCCipher()
        self.client_socket = None
        self.is_connected = False
        
        self.AES_KEY = os.urandom(16)
        self.AES_IV = os.urandom(16)

        self.DES_KEY = os.urandom(8)
        self.DES_IV = os.urandom(8)

        self.create_ui()
        self.connect_to_server()
        
    def create_ui(self):
        header = tk.Frame(self.window, bg="#2196F3", height=80)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="🔒 İSTEMCİ - Şifreleme Servisi", 
                 font=("Arial", 20, "bold"), bg="#2196F3", fg="white").pack(pady=20)
        
        content = tk.Frame(self.window, bg="white")
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        status_frame = tk.LabelFrame(content, text="📡 Bağlantı Durumu", 
                                     font=("Arial", 11, "bold"), bg="white", fg="#2196F3")
        status_frame.pack(fill=tk.X, pady=10)
        
        self.status_label = tk.Label(status_frame, text="⏳ Sunucuya bağlanılıyor...", 
                                      font=("Arial", 10), bg="white", fg="orange")
        self.status_label.pack(pady=10)
        
        tk.Label(content, text="🔐 Şifreleme Yöntemi", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        
        self.cipher_var = tk.StringVar()
        cipher_combo = ttk.Combobox(content, textvariable=self.cipher_var,
                                       font=("Arial", 11), width=50, state="readonly")
        cipher_combo['values'] = ("Pigpen Cipher (Anahtarsız)", "Polybius Cipher (Anahtarsız)", "Route Cipher (Spiral-Saat Yönü)", "Columnar Transposition (Anahtar Kelime)", "Caesar Cipher (Kaydırma)", 
                                     "Substitution Cipher", "Vigenere Cipher", "Playfair Cipher", 
                                     "Rail Fence Cipher (Ray Sayısı)","Hill Cipher", "Hash (MD5)","AES-128 (Kütüphaneli)","AES-128 (RSA ile Güvenli)","AES-128 (ECC ile Güvenli)","DES (Kütüphaneli)","AES (Manuel/Basit)","DES (Manual/Basit)")
        cipher_combo.current(0)
        cipher_combo.pack(pady=5)
        
        tk.Label(content, text="🔑 Anahtar", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.key_entry = tk.Entry(content, font=("Arial", 11), width=52)
        self.key_entry.insert(0," ") 
        self.key_entry.config(state=tk.DISABLED, fg="#888")
        self.key_entry.pack(pady=5)
        
        cipher_combo.bind("<<ComboboxSelected>>", self.update_key_field)
        
        tk.Label(content, text="💬 Mesaj", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.msg_text = tk.Text(content, font=("Arial", 11), height=5, width=65, wrap=tk.WORD)
        self.msg_text.pack(pady=5)
        
        btn_frame = tk.Frame(content, bg="white")
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="🔒 Şifrele", command=self.encrypt,
                   bg="#2196F3", fg="white", font=("Arial", 11, "bold"),
                   padx=30, pady=10, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="📤 Sunucuya Gönder", command=self.send_to_server,
                   bg="#4CAF50", fg="white", font=("Arial", 11, "bold"),
                   padx=30, pady=10, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        tk.Label(content, text="🔐 Şifrelenmiş Mesaj", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.encrypted_text = tk.Text(content, font=("Courier", 10), 
                                      height=5, width=65, wrap=tk.WORD, bg="#e3f2fd")
        self.encrypted_text.pack(pady=5)
        
        tk.Label(content, text="✅ Sunucudan Gelen Deşifrelenmiş Mesaj", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.response_text = tk.Text(content, font=("Courier", 10), 
                                     height=5, width=65, wrap=tk.WORD, bg="#e8f5e9")
        self.response_text.pack(pady=5)
        
        tk.Label(content, text="📋 İşlem Logları", 
                 font=("Arial", 10, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.log_text = scrolledtext.ScrolledText(content, font=("Courier", 9), 
                                                  height=4, wrap=tk.WORD, bg="#f5f5f5")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
    def update_key_field(self, event):
        selected_cipher = self.cipher_var.get()
        self.key_entry.config(state=tk.NORMAL, fg="black")
        self.key_entry.delete(0, tk.END)

        if "Hash" in selected_cipher or "Polybius" in selected_cipher or "Pigpen" in selected_cipher:
            self.key_entry.insert(0, "Anahtar gerekmez.")
            self.key_entry.config(state=tk.DISABLED, fg="#888")
        elif "AES-128 (RSA ile Güvenli)" in selected_cipher:
            try:
                # Key Server kontrolü yap (Bağlantı testi)
                self.get_public_key_from_server()
                aes_key_hex = self.AES_KEY.hex()
                self.key_entry.insert(0, f"AES Key (RSA ile şifrelenip yollanacak): {aes_key_hex}")
                self.key_entry.config(state=tk.DISABLED, fg="#9C27B0")
            except Exception:
                self.key_entry.insert(0, "HATA: Key Server (Port 5556) Kapalı!")
                self.key_entry.config(state=tk.DISABLED, fg="red")
        elif "AES-128 (ECC ile Güvenli)" in selected_cipher:
            try:
                # Key Server kontrolü yap (Bağlantı testi)
                self.get_public_key_from_server("ECC")
                aes_key_hex = self.AES_KEY.hex()
                self.key_entry.insert(0, f"AES Key (ECC ile şifrelenip yollanacak): {aes_key_hex}")
                self.key_entry.config(state=tk.DISABLED, fg="#9C27B0")
            except Exception:
                self.key_entry.insert(0, "HATA: Key Server (Port 5556) Kapalı!")
                self.key_entry.config(state=tk.DISABLED, fg="red")
        elif "AES-128" in selected_cipher:
            aes_key_hex = self.AES_KEY.hex()
            self.key_entry.insert(0, f"AES Anahtarı (16B): {aes_key_hex}")
            self.key_entry.config(state=tk.DISABLED, fg="#005a8d")
        elif "DES" in selected_cipher:
            des_key_hex = self.DES_KEY.hex()
            self.key_entry.insert(0, f"DES Anahtarı (8B): {des_key_hex}")
            self.key_entry.config(state=tk.DISABLED, fg="#005a8d")
        elif "AES (Manuel/Basit)" in selected_cipher:
            aes_key_hex = self.AES_KEY.hex()
            self.key_entry.insert(0, f"AES Anahtarı (16B): {aes_key_hex} (Manuel)")
            self.key_entry.config(state=tk.DISABLED, fg="#005a8d")
        elif "DES (Manuel/Basit)" in selected_cipher:
            des_key_hex = self.DES_KEY.hex()
            self.key_entry.insert(0, f"DES Anahtarı (8B): {des_key_hex} (Manuel)")
            self.key_entry.config(state=tk.DISABLED, fg="#005a8d")    
        elif "Hill Cipher" in selected_cipher:
            self.key_entry.insert(0, "9,4,5,7 (2x2 Matris Elemanları: a,b,c,d - Sadece 2x2 desteklenir)")
        elif "Route Cipher" in selected_cipher:
            self.key_entry.insert(0, "5 (Matris Genişliği)")
        elif "Columnar" in selected_cipher:
            self.key_entry.insert(0, "TRUVA (Anahtar Kelime)")
        elif "Caesar" in selected_cipher:
            self.key_entry.insert(0, "3 (Kaydırma Miktarı)")
        elif "Substitution" in selected_cipher:
            self.key_entry.insert(0, "QWERTYUIOPASDFGHJKLZXCVBNM (26 benzersiz harf)")
        elif "Vigenere" in selected_cipher:
            self.key_entry.insert(0, "KEYWORD (Anahtar Kelime)")
        elif "Playfair" in selected_cipher:
            self.key_entry.insert(0, "PLAYFAIR (Anahtar Kelime - J/I kuralı)")
        elif "Rail Fence" in selected_cipher:
            self.key_entry.insert(0, "2 (Ray Sayısı)")
        else:
            self.key_entry.insert(0, "") 

        
    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('localhost', 5555))
            self.is_connected = True
            
            self.log("✅ Sunucuya bağlanıldı: localhost:5555")
            self.status_label.config(text="✅ Sunucuya bağlı", fg="green")
            
        except Exception as e:
            self.log(f"❌ Sunucuya bağlanılamadı: {e}")
            self.status_label.config(text=f"❌ Bağlantı Hatası: {e}", fg="red")
            messagebox.showerror("Bağlantı Hatası", 
                                 "Sunucuya bağlanılamadı!\n\nLütfen önce server.py'yi çalıştırın.")
    
    def encrypt(self):
        msg = self.msg_text.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        cipher = self.cipher_var.get()
        
        if not msg:
            messagebox.showerror("Hata", "Lütfen bir mesaj girin!")
            return
        
        if ("Hash" not in cipher and "Polybius" not in cipher and "Pigpen" not in cipher) and not key:
            messagebox.showerror("Hata", "Lütfen bir anahtar girin!")
            return
        
        if "Hash" in cipher or "Polybius" in cipher or "Pigpen" in cipher:
            key = ""
        
        try:
            if "DES (Manuel/Basit)" in cipher:
                encrypted = self.des.encrypt_manual(msg, self.DES_KEY)
            elif "AES (Manuel/Basit)" in cipher:
                # Manuel AES, sadece key_bytes kullanır
                encrypted = self.aes.encrypt_manual(msg, self.AES_KEY)
            elif "DES" in cipher:
                encrypted = self.des.encrypt_lib(msg, self.DES_KEY, self.DES_IV)
            elif "AES-128 (RSA ile Güvenli)" in cipher:
                # Key Server kontrolü: Sunucu kapalıysa şifreleme yapma (Güvenlik gereği)
                try:
                    self.get_public_key_from_server()
                except Exception:
                    messagebox.showerror("Hata", "Key Server (Port 5556) Kapalı!\nBu yöntem için Key Server aktif olmalıdır.")
                    return
                encrypted = self.aes.encrypt_lib(msg, self.AES_KEY, self.AES_IV)
            elif "AES-128 (ECC ile Güvenli)" in cipher:
                # Key Server kontrolü
                try:
                    self.get_public_key_from_server("ECC")
                except Exception:
                    messagebox.showerror("Hata", "Key Server (Port 5556) Kapalı!\nBu yöntem için Key Server aktif olmalıdır.")
                    return
                encrypted = self.aes.encrypt_lib(msg, self.AES_KEY, self.AES_IV)
            elif "AES-128" in cipher:
                encrypted = self.aes.encrypt_lib(msg, self.AES_KEY, self.AES_IV)
            elif "Hill Cipher" in cipher:
                encrypted = self.crypto.hill_encrypt(msg, key)
            elif "Pigpen" in cipher:
                encrypted = self.crypto.pigpen_encrypt(msg)
            elif "Hill Cipher" in cipher:
                encrypted = self.crypto.hill_encrypt(msg, key)
            elif "Polybius" in cipher:
                encrypted = self.crypto.polybius_encrypt(msg)
            elif "Route Cipher" in cipher:
                encrypted = self.crypto.route_encrypt(msg, key)
            elif "Columnar" in cipher:
                encrypted = self.crypto.columnar_encrypt(msg, key)
            elif "Caesar" in cipher:
                encrypted = self.crypto.caesar_encrypt(msg, int(key))
            elif "Substitution" in cipher:
                encrypted = self.crypto.substitution_encrypt(msg, key)
            elif "Vigenere" in cipher:
                encrypted = self.crypto.vigenere_encrypt(msg, key)
            elif "Playfair" in cipher:
                encrypted = self.crypto.playfair_encrypt(msg, key)
            elif "Rail Fence" in cipher:
                encrypted = self.crypto.rail_fence_encrypt(msg, key)
            elif "Hash" in cipher:
                encrypted = self.crypto.md5_hash(msg)
            else:
                messagebox.showerror("Hata", "Lütfen bir şifreleme yöntemi seçin!")
                return
            
            self.encrypted_text.delete("1.0", tk.END)
            self.encrypted_text.insert("1.0", encrypted)
            
            self.log(f"🔒 Mesaj şifrelendi - Yöntem: {cipher}")
            
        except ValueError as e:
            messagebox.showerror("Hata", f"Anahtar veya mesaj formatı hatası: {str(e)}")
        except Exception as e:
            messagebox.showerror("Hata", f"Şifreleme hatası: {str(e)}")
    
    def get_public_key_from_server(self, key_type="RSA"):
        """Key Server'dan (Port 5556) Public Key'i çeker"""
        try:
            key_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            key_socket.connect(('localhost', 5556))
            self.log(f"🔑 Key Server'a (Port 5556) bağlanıldı, {key_type} Public Key isteniyor...")
            key_socket.send(key_type.encode())
            pub_key_pem = key_socket.recv(4096)
            key_socket.close()
            return pub_key_pem
        except Exception as e:
            raise Exception(f"Key Server'a ulaşılamadı: {e}")

    def send_to_server(self):
        if not self.is_connected:
            messagebox.showerror("Hata", "Sunucuya bağlı değilsiniz!")
            return
        
        encrypted_msg = self.encrypted_text.get("1.0", tk.END).strip()
        if not encrypted_msg:
            messagebox.showerror("Hata", "Lütfen önce mesajı şifreleyin!")
            return
    
        key = self.key_entry.get().strip()
        cipher = self.cipher_var.get()
        
        try:
            effective_key = ""
            effective_iv = ""

            if "DES (Manuel/Basit)" in cipher:
                effective_key = self.DES_KEY.hex()
                effective_iv = ""

            elif "AES (Manuel/Basit)" in cipher:
                effective_key = self.AES_KEY.hex()
                effective_iv = "" # Manuelde IV kullanmıyoruz (basitleştirilmiş versiyon)

            elif "DES" in cipher:
                effective_key = self.DES_KEY.hex()
                effective_iv = self.DES_IV.hex()
            elif "AES-128 (RSA ile Güvenli)" in cipher:
                # 1. Key Server'dan Public Key al
                pub_key_pem = self.get_public_key_from_server()
                
                # Gelen verinin gerçekten bir anahtar olup olmadığını kontrol et
                if not pub_key_pem.startswith(b'-----BEGIN PUBLIC KEY'):
                    error_msg = pub_key_pem.decode('utf-8', errors='ignore')
                    self.log(f"❌ Key Server Hatası: {error_msg}")
                    messagebox.showerror("Key Server Hatası", f"Anahtar alınamadı:\n{error_msg}")
                    return

                self.log("✅ Public Key alındı.")
                
                # 2. AES Anahtarını RSA ile şifrele
                pub_key = self.rsa.load_public_key_from_bytes(pub_key_pem)
                encrypted_aes_key = self.rsa.encrypt_key(self.AES_KEY, pub_key)
                effective_key = encrypted_aes_key.hex() # Şifreli anahtarı hex olarak gönder
                effective_iv = self.AES_IV.hex()
            elif "AES-128 (ECC ile Güvenli)" in cipher:
                # 1. Key Server'dan ECC Public Key al
                pub_key_pem = self.get_public_key_from_server("ECC")
                
                if not pub_key_pem.startswith(b'-----BEGIN PUBLIC KEY'):
                    error_msg = pub_key_pem.decode('utf-8', errors='ignore')
                    messagebox.showerror("Key Server Hatası", f"Anahtar alınamadı:\n{error_msg}")
                    return

                # 2. AES Anahtarını ECC ile şifrele
                pub_key = self.ecc.load_public_key_from_bytes(pub_key_pem)
                encrypted_aes_key = self.ecc.encrypt_key(self.AES_KEY, pub_key)
                effective_key = encrypted_aes_key.hex()
                effective_iv = self.AES_IV.hex()
            elif "AES-128" in cipher:
                # AES için anahtar ve IV'yi hex olarak gönder
                effective_key = self.AES_KEY.hex()
                effective_iv = self.AES_IV.hex()
            elif "Hash" not in cipher and "Polybius" not in cipher and "Pigpen" not in cipher:
                effective_key = key

            request = json.dumps({
                'cipher': cipher,
                'key': effective_key, 
                'iv': effective_iv,
                'message': encrypted_msg
            })
            
            self.client_socket.send(request.encode('utf-8'))
            self.log(f"📤 Şifreli mesaj sunucuya gönderildi")
            
            response = self.client_socket.recv(4096).decode('utf-8')
            data = json.loads(response)
            
            if data.get('status') == 'success':
                self.response_text.delete("1.0", tk.END)
                self.response_text.insert("1.0", "✅ Mesaj sunucuya başarıyla iletildi ve deşifre edildi.")
                self.log(f"✅ Sunucu onayı alındı")
            else:
                messagebox.showerror("Hata", f"Sunucu tarafında bir hata oluştu: {data.get('decrypted', 'Bilinmeyen hata')}")
                
        except Exception as e:
            self.log(f"❌ Gönderim hatası: {e}")
            messagebox.showerror("Hata", f"Sunucuya gönderim başarısız: {e}")
            self.is_connected = False
            self.status_label.config(text="❌ Bağlantı koptu", fg="red")
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def run(self):
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.window.mainloop()
    
    def on_closing(self):
        if self.client_socket:
            self.client_socket.close()
        self.window.destroy()

if __name__ == "__main__":
    ClientApp().run()