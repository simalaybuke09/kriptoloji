import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import json
from datetime import datetime
from crypto_functions import CryptoFunctions
from aes_cipher import AESCipher
from des_cipher import DESCipher
from rsa_cipher import RSACipher
from ecc_cipher import ECCCipher
import os

class ServerApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🔓 Sunucu - Deşifreleme Servisi")
        self.window.geometry("800x700")
        self.window.configure(bg="#f0f0f0")
        
        self.crypto = CryptoFunctions()
        self.aes = AESCipher()
        self.des = DESCipher()
        self.rsa = RSACipher()
        self.ecc = ECCCipher()
        self.server_socket = None
        self.client_socket = None
        self.is_running = False
        
        self.create_ui()
        self.start_server()
        
        # RSA Anahtarlarını Üret ve Public Key'i Kaydet (Key Server için)
        self.log("🔑 RSA Anahtarları üretiliyor...")
        self.private_key, self.public_key = self.rsa.generate_keys()
        self.rsa.save_public_key(self.public_key, "public_key.pem")
        self.log("✅ Public Key 'public_key.pem' olarak kaydedildi.")

        # ECC Anahtarlarını Üret ve Public Key'i Kaydet
        self.log("🔑 ECC Anahtarları üretiliyor...")
        self.ecc_private_key, self.ecc_public_key = self.ecc.generate_keys()
        self.ecc.save_public_key(self.ecc_public_key, "public_key_ecc.pem")
        self.log("✅ ECC Public Key 'public_key_ecc.pem' olarak kaydedildi.")

    def create_ui(self):
        header = tk.Frame(self.window, bg="#4CAF50", height=80)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="🔓 SUNUCU - Deşifreleme Servisi", 
                 font=("Arial", 20, "bold"), bg="#4CAF50", fg="white").pack(pady=20)
        
        content = tk.Frame(self.window, bg="white")
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        status_frame = tk.LabelFrame(content, text="📡 Bağlantı Durumu", 
                                     font=("Arial", 11, "bold"), bg="white", fg="#4CAF50")
        status_frame.pack(fill=tk.X, pady=10)
        
        self.status_label = tk.Label(status_frame, text="⏳ Başlatılıyor...", 
                                      font=("Arial", 10), bg="white", fg="orange")
        self.status_label.pack(pady=10)
        
        tk.Label(content, text="📨 Gelen Şifreli Mesajlar", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        
        self.received_text = scrolledtext.ScrolledText(content, font=("Courier", 10), 
                                                      height=8, wrap=tk.WORD, bg="#fff3e0")
        self.received_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        tk.Label(content, text="✅ Deşifrelenmiş Mesajlar", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        
        self.decrypted_text = scrolledtext.ScrolledText(content, font=("Courier", 10), 
                                                       height=8, wrap=tk.WORD, bg="#e8f5e9")
        self.decrypted_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        tk.Label(content, text="📋 İşlem Logları", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        
        self.log_text = scrolledtext.ScrolledText(content, font=("Courier", 9), 
                                                   height=6, wrap=tk.WORD, bg="#f5f5f5")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        btn_frame = tk.Frame(content, bg="white")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="🗑️ Temizle", command=self.clear_all,
                   bg="#FF9800", fg="white", font=("Arial", 10, "bold"),
                   padx=20, pady=8, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹️ Sunucuyu Durdur", command=self.stop_server,
                                 bg="#f44336", fg="white", font=("Arial", 10, "bold"),
                                 padx=20, pady=8, relief=tk.FLAT, cursor="hand2")
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', 5555))
            self.server_socket.listen(1)
            self.is_running = True
            
            self.log("✅ Sunucu başlatıldı: localhost:5555")
            self.status_label.config(text="✅ Aktif - İstemci bekleniyor...", fg="green")
            
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
        except Exception as e:
            self.log(f"❌ Sunucu başlatma hatası: {e}")
            self.status_label.config(text=f"❌ Hata: {e}", fg="red")
    
    def accept_connections(self):
        while self.is_running:
            try:
                self.client_socket, addr = self.server_socket.accept()
                self.log(f"🔗 İstemci bağlandı: {addr}")
                self.status_label.config(text=f"✅ İstemci bağlı: {addr}", fg="green")
                
                threading.Thread(target=self.receive_messages, daemon=True).start()
                
            except Exception as e:
                if self.is_running:
                    self.log(f"❌ Bağlantı hatası: {e}")
    
    def receive_messages(self):
        while self.is_running and self.client_socket:
            try:
                data = self.client_socket.recv(4096).decode('utf-8')
                if not data:
                    break
                if not data.strip(): 
                    continue # Döngünün başına dön

                request = json.loads(data)
                cipher = request.get('cipher')
                key = request.get('key')
                message = request.get('message')
                iv = request.get('iv', '')

                self.log(f"📨 Mesaj alındı - Yöntem: {cipher}, Anahtar: {key}, IV: {iv[:8]}...")
                self.received_text.insert(tk.END, f"{message}\n")
                self.received_text.see(tk.END)
                
                decrypted = self.decrypt_message(message, cipher, key, iv)
                
                self.log(f"✅ Deşifreleme tamamlandı")
                self.decrypted_text.insert(tk.END, f"{decrypted}\n")
                self.decrypted_text.see(tk.END)
                # HATA ÖNLEME: Gelen veri boş veya anlamsız ise atla

                
                response = json.dumps({
                    'status': 'success',
                })
                self.client_socket.send(response.encode('utf-8'))
                
            except Exception as e:
                self.log(f"❌ Mesaj işleme hatası: {e}")
                break
        
        if self.client_socket:
            self.client_socket.close()
            self.status_label.config(text="⏳ İstemci bekleniyor...", fg="orange")
    
    def decrypt_message(self, message, cipher, key, iv=""):
        try:
            if "DES (Manuel/Basit)" in cipher:
                key_bytes = bytes.fromhex(key)
                return self.des.decrypt_manual(message, key_bytes)
            if "AES (Manuel/Basit)" in cipher:
                # Deşifreleme, manuelde desteklenmez (uyarı verir)
                key_bytes = bytes.fromhex(key)
                return self.aes.decrypt_manual(message, key_bytes)
            if "DES" in cipher:
                key_bytes = bytes.fromhex(key)
                iv_bytes = bytes.fromhex(iv)
                return self.des.decrypt_lib(message, key_bytes, iv_bytes)
            if "AES-128 (RSA ile Güvenli)" in cipher:
                # 1. RSA ile şifrelenmiş AES anahtarını çöz
                encrypted_aes_key = bytes.fromhex(key)
                aes_key = self.rsa.decrypt_key(encrypted_aes_key, self.private_key)
                # 2. Çözülen AES anahtarı ile mesajı deşifre et
                iv_bytes = bytes.fromhex(iv)
                return self.aes.decrypt_lib(message, aes_key, iv_bytes)
            if "AES-128 (ECC ile Güvenli)" in cipher:
                # 1. ECC ile şifrelenmiş AES anahtarını çöz
                encrypted_aes_key = bytes.fromhex(key)
                aes_key = self.ecc.decrypt_key(encrypted_aes_key, self.ecc_private_key)
                # 2. Çözülen AES anahtarı ile mesajı deşifre et
                iv_bytes = bytes.fromhex(iv)
                return self.aes.decrypt_lib(message, aes_key, iv_bytes)
            if "AES-128" in cipher:
                key_bytes = bytes.fromhex(key)
                iv_bytes = bytes.fromhex(iv)
                return self.aes.decrypt_lib(message, key_bytes, iv_bytes)
            elif "Hill Cipher" in cipher:
                return self.crypto.hill_decrypt(message, key)
            if "Pigpen" in cipher:
                return self.crypto.pigpen_decrypt(message)
            elif "Polybius" in cipher:
                return self.crypto.polybius_decrypt(message)
            elif "Route Cipher" in cipher:
                return self.crypto.route_decrypt(message, key)
            elif "Columnar" in cipher:
                return self.crypto.columnar_decrypt(message, key)
            elif "Caesar" in cipher:
                return self.crypto.caesar_decrypt(message, int(key))
            elif "Substitution" in cipher:
                return self.crypto.substitution_decrypt(message, key)
            elif "Vigenere" in cipher:
                return self.crypto.vigenere_decrypt(message, key)
            elif "Playfair" in cipher:
                return self.crypto.playfair_decrypt(message, key)
            elif "Rail Fence" in cipher:
                return self.crypto.rail_fence_decrypt(message, key)
            elif "Hash" in cipher:
                return "⚠️ MD5 tek yönlüdür, deşifrelenemez!"
            else:
                return "❌ Bilinmeyen şifreleme yöntemi"
        except Exception as e:
            return f"❌ Deşifreleme hatası: {e}"
    
    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def clear_all(self):
        self.received_text.delete(1.0, tk.END)
        self.decrypted_text.delete(1.0, tk.END)
        self.log("🗑️ Ekran temizlendi")
    
    def stop_server(self):
        self.is_running = False
        if self.client_socket:
            self.client_socket.close()
        if self.server_socket:
            self.server_socket.close()
        self.log("⏹️ Sunucu durduruldu")
        self.status_label.config(text="⏹️ Sunucu durduruldu", fg="red")
        self.stop_btn.config(state=tk.DISABLED)
    
    def run(self):
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.window.mainloop()
    
    def on_closing(self):
        self.stop_server()
        # Sunucu kapanınca Public Key dosyasını sil (Güvenlik ve Test için)
        if os.path.exists("public_key.pem"):
            os.remove("public_key.pem")
        if os.path.exists("public_key_ecc.pem"):
            os.remove("public_key_ecc.pem")
        self.window.destroy()

if __name__ == "__main__":
    ServerApp().run()