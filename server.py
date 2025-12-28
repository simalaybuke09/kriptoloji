import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import json
from datetime import datetime
from methods.aes_manual import AESManual
from methods.aes_lib import AESLib
from methods.des_manual import DESManual
from methods.des_lib import DESLib
from methods.rsa_cipher import RSACipher
from methods.ecc_cipher import ECCCipher
from methods.hill_cipher import HillCipher
from methods.pigpen_cipher import PigpenCipher
from methods.polybius_cipher import PolybiusCipher
from methods.columnar_cipher import ColumnarCipher
from methods.route_cipher import RouteCipher
from methods.caesar_cipher import CaesarCipher
from methods.substitution_cipher import SubstitutionCipher
from methods.vigenere_cipher import VigenereCipher
from methods.playfair_cipher import PlayfairCipher
from methods.rail_fence_cipher import RailFenceCipher
from methods.hash_cipher import HashCipher
from methods.affine_cipher import AffineCipher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
import os

class ServerApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🔓 Sunucu - Deşifreleme Servisi")
        self.window.geometry("800x700")
        self.window.configure(bg="#f0f0f0")
        
        self.aes_man = AESManual()
        self.aes_lib = AESLib()
        self.des_man = DESManual()
        self.des_lib = DESLib()
        self.rsa = RSACipher()
        self.ecc = ECCCipher()
        self.hill = HillCipher()
        self.pigpen = PigpenCipher()
        self.polybius = PolybiusCipher()
        self.columnar = ColumnarCipher()
        self.route = RouteCipher()
        self.caesar = CaesarCipher()
        self.substitution = SubstitutionCipher()
        self.vigenere = VigenereCipher()
        self.playfair = PlayfairCipher()
        self.rail_fence = RailFenceCipher()
        self.hash = HashCipher()
        self.affine = AffineCipher()
        
        self.server_socket = None
        self.client_socket = None
        self.is_running = False
        self.transport_key = None # Tünel şifreleme anahtarı
        
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
                client_sock, addr = self.server_socket.accept()
                self.log(f"🔗 İstemci bağlandı: {addr}")
                self.status_label.config(text=f"✅ İstemci bağlı: {addr}", fg="green")
                
                # Eski bağlantı varsa kapat (Tek istemci mantığı)
                if self.client_socket:
                    try: self.client_socket.close()
                    except: pass
                
                self.client_socket = client_sock

                # Handshake işlemini thread'e taşı (Ana döngüyü bloklamamak için)
                threading.Thread(target=self.handle_client_handshake, daemon=True).start()
                
            except Exception as e:
                if self.is_running:
                    self.log(f"❌ Bağlantı hatası: {e}")

    def handle_client_handshake(self):
        # --- GÜVENLİ TÜNEL EL SIKIŞMASI (ECDH Handshake) ---
        try:
            # 1. İstemcinin Public Key'ini al
            client_pub_bytes = self.client_socket.recv(4096)
            client_pub = self.ecc.load_public_key_from_bytes(client_pub_bytes)
            
            # 2. Kendi geçici anahtarlarımızı üret
            my_priv, my_pub = self.ecc.generate_keys()
            
            # 3. Ortak Taşıma Anahtarını türet
            self.transport_key = self.ecc.derive_transport_key(my_priv, client_pub)
            
            # 4. Kendi Public Key'imizi gönder
            my_pub_bytes = my_pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self.client_socket.send(my_pub_bytes)
            self.log("✅ Güvenli tünel kuruldu (ECDH).")
            
            # Handshake başarılı, mesajları dinlemeye başla
            self.receive_messages()
            
        except Exception as e:
            self.log(f"❌ Handshake hatası: {e}")
            if self.client_socket:
                try: self.client_socket.close()
                except: pass
    
    def receive_messages(self):
        while self.is_running and self.client_socket:
            try:
                # Şifreli tünel verisini al
                data = self.client_socket.recv(4096)
                if not data:
                    break

                # --- TÜNEL DEŞİFRELEME (AES-GCM) ---
                aesgcm = AESGCM(self.transport_key)
                nonce = data[:12]
                ciphertext = data[12:]
                
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                json_str = plaintext.decode('utf-8')
                
                request = json.loads(json_str)
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
                
                # Yanıtı da şifreleyerek gönder
                resp_nonce = os.urandom(12)
                resp_ciphertext = aesgcm.encrypt(resp_nonce, response.encode('utf-8'), None)
                self.client_socket.send(resp_nonce + resp_ciphertext)
                
            except Exception as e:
                self.log(f"❌ Mesaj işleme hatası: {e}")
                break
        
        if self.client_socket:
            self.client_socket.close()
            self.status_label.config(text="⏳ İstemci bekleniyor...", fg="orange")
    
    def decrypt_message(self, message, cipher, key, iv=""):
        try:
            if "DES (Manuel/Basit)" in cipher:
                try: key_hex, _, ciphertext = message.split("||", 2)
                except ValueError: return "❌ Hata: Mesaj formatı geçersiz."
                key_bytes = bytes.fromhex(key_hex)
                return self.des_man.decrypt(ciphertext, key_bytes)

            if "AES (Manuel/Basit)" in cipher:
                try: key_hex, _, ciphertext = message.split("||", 2)
                except ValueError: return "❌ Hata: Mesaj formatı geçersiz."
                key_bytes = bytes.fromhex(key_hex)
                return self.aes_man.decrypt(ciphertext, key_bytes)
            if "AES-128 (RSA ile Güvenli)" in cipher:
                # Mesaj formatı: EncryptedKey||IV||Ciphertext
                # AÇIKLAMA: İstemci, mesajı şifrelediği AES anahtarını (Session Key) 
                # bizim Public Key'imizle şifreleyip paketin başına ekledi.
                # Önce bu şifreli anahtarı çözüp, asıl mesajı açacak anahtarı elde ediyoruz.
                try:
                    enc_key_hex, iv_hex, ciphertext = message.split("||", 2)
                except ValueError:
                    return "❌ Hata: Mesaj formatı geçersiz (Key paketlenmemiş)."
                
                # 1. RSA ile şifrelenmiş AES anahtarını çöz (Paketten al)
                encrypted_aes_key = bytes.fromhex(enc_key_hex)
                aes_key = self.rsa.decrypt_key(encrypted_aes_key, self.private_key)
                # 2. Çözülen AES anahtarı ile mesajı deşifre et (Paketten IV ve Mesajı al)
                iv_bytes = bytes.fromhex(iv_hex)
                return self.aes_lib.decrypt(ciphertext, aes_key, iv_bytes)
            if "AES-128 (ECC ile Güvenli)" in cipher:
                try:
                    enc_key_hex, iv_hex, ciphertext = message.split("||", 2)
                except ValueError:
                    return "❌ Hata: Mesaj formatı geçersiz."
                
                encrypted_aes_key = bytes.fromhex(enc_key_hex)
                aes_key = self.ecc.decrypt_key(encrypted_aes_key, self.ecc_private_key)
                iv_bytes = bytes.fromhex(iv_hex)
                return self.aes_lib.decrypt(ciphertext, aes_key, iv_bytes)
            if "DES (RSA ile Güvenli)" in cipher:
                try:
                    enc_key_hex, iv_hex, ciphertext = message.split("||", 2)
                except ValueError:
                    return "❌ Hata: Mesaj formatı geçersiz (Key paketlenmemiş)."
                
                encrypted_des_key = bytes.fromhex(enc_key_hex)
                des_key = self.rsa.decrypt_key(encrypted_des_key, self.private_key)
                iv_bytes = bytes.fromhex(iv_hex)
                return self.des_lib.decrypt(ciphertext, des_key, iv_bytes)
            if "DES (ECC ile Güvenli)" in cipher:
                try:
                    enc_key_hex, iv_hex, ciphertext = message.split("||", 2)
                except ValueError:
                    return "❌ Hata: Mesaj formatı geçersiz."
                
                encrypted_des_key = bytes.fromhex(enc_key_hex)
                des_key = self.ecc.decrypt_key(encrypted_des_key, self.ecc_private_key)
                iv_bytes = bytes.fromhex(iv_hex)
                return self.des_lib.decrypt(ciphertext, des_key, iv_bytes)
            if "DES" in cipher:
                try: key_hex, iv_hex, ciphertext = message.split("||", 2)
                except ValueError: return "❌ Hata: Mesaj formatı geçersiz."
                key_bytes = bytes.fromhex(key_hex)
                iv_bytes = bytes.fromhex(iv_hex)
                return self.des_lib.decrypt(ciphertext, key_bytes, iv_bytes)
            if "AES-128" in cipher:
                try: key_hex, iv_hex, ciphertext = message.split("||", 2)
                except ValueError: return "❌ Hata: Mesaj formatı geçersiz."
                key_bytes = bytes.fromhex(key_hex)
                iv_bytes = bytes.fromhex(iv_hex)
                return self.aes_lib.decrypt(ciphertext, key_bytes, iv_bytes)
            elif "Hill Cipher" in cipher:
                return self.hill.decrypt(message, key)
            if "Pigpen" in cipher:
                return self.pigpen.decrypt(message)
            elif "Polybius" in cipher:
                return self.polybius.decrypt(message)
            elif "Route Cipher" in cipher:
                return self.route.decrypt(message, key)
            elif "Columnar" in cipher:
                return self.columnar.decrypt(message, key)
            elif "Caesar" in cipher:
                return self.caesar.decrypt(message, int(key))
            elif "Affine" in cipher:
                return self.affine.decrypt(message, key)
            elif "Substitution" in cipher:
                return self.substitution.decrypt(message, key)
            elif "Vigenere" in cipher:
                return self.vigenere.decrypt(message, key)
            elif "Playfair" in cipher:
                return self.playfair.decrypt(message, key)
            elif "Rail Fence" in cipher:
                return self.rail_fence.decrypt(message, key)
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