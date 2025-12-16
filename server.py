import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import json
from datetime import datetime
from crypto_functions import CryptoFunctions

class ServerApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🔓 Sunucu - Deşifreleme Servisi")
        self.window.geometry("800x700")
        self.window.configure(bg="#f0f0f0")
        
        self.crypto = CryptoFunctions()
        self.server_socket = None
        self.client_socket = None
        self.is_running = False
        
        self.create_ui()
        self.start_server()
        
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
                    'decrypted': decrypted
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
            if "DES" in cipher:
                key_bytes = bytes.fromhex(key)
                iv_bytes = bytes.fromhex(iv)
                return self.crypto.des_decrypt_lib(message, key_bytes, iv_bytes)
            if "AES-128" in cipher:
                key_bytes = bytes.fromhex(key)
                iv_bytes = bytes.fromhex(iv)
                return self.crypto.aes_decrypt_lib(message, key_bytes, iv_bytes)
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
        self.window.destroy()

if __name__ == "__main__":
    ServerApp().run()