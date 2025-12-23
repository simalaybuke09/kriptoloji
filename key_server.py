import tkinter as tk
from tkinter import scrolledtext
import socket
import threading
from datetime import datetime
import os

class KeyServerApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🔑 Anahtar Sunucusu (CA)")
        self.window.geometry("600x500")
        self.window.configure(bg="#f0f0f0")
        
        self.server_socket = None
        self.is_running = False
        self.request_count = 0
        
        self.create_ui()
        self.start_server()
        
    def create_ui(self):
        header = tk.Frame(self.window, bg="#9C27B0", height=80)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="🔑 ANAHTAR SUNUCUSU (CA)", 
                 font=("Arial", 18, "bold"), bg="#9C27B0", fg="white").pack(pady=20)
        
        content = tk.Frame(self.window, bg="white")
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        self.status_label = tk.Label(content, text="⏳ Başlatılıyor...", 
                                      font=("Arial", 10), bg="white", fg="orange")
        self.status_label.pack(pady=10)
        
        tk.Label(content, text="📋 İstek Logları", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        
        self.log_text = scrolledtext.ScrolledText(content, font=("Courier", 9), 
                                                   height=15, wrap=tk.WORD, bg="#f3e5f5")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
    def start_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('localhost', 5556)) # Farklı port: 5556
            self.server_socket.listen(5)
            self.is_running = True
            
            self.log("✅ Key Server başlatıldı: localhost:5556")
            self.status_label.config(text="✅ Aktif - Public Key Dağıtılıyor", fg="green")
            
            threading.Thread(target=self.accept_connections, daemon=True).start()
            
        except Exception as e:
            self.log(f"❌ Başlatma hatası: {e}")
    
    def accept_connections(self):
        while self.is_running:
            try:
                client_sock, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()
            except Exception as e:
                if self.is_running: self.log(f"Hata: {e}")

    def handle_client(self, client_sock, addr):
        try:
            self.log(f"🔗 İstek geldi: {addr}")
            # Public Key dosyasını oku (Server.py tarafından oluşturulmuş olmalı)
            if os.path.exists("public_key.pem"):
                with open("public_key.pem", "rb") as f:
                    pub_key_data = f.read()
                client_sock.send(pub_key_data)
                self.request_count += 1
                self.status_label.config(text=f"✅ Aktif - {self.request_count} Kez Anahtar Gönderildi")
                self.log(f"📤 (#{self.request_count}) Public Key gönderildi -> {addr}")
            else:
                msg = "❌ Public Key henüz oluşturulmadı (App Server'ı başlatın)."
                client_sock.send(msg.encode('utf-8'))
                self.log("⚠️ Public Key dosyası bulunamadı!")
        except Exception as e:
            self.log(f"❌ İletişim hatası: {e}")
        finally:
            client_sock.close()

    def log(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    KeyServerApp().run()