import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import json
from datetime import datetime
from crypto_functions import CryptoFunctions

class ClientApp:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🔒 İstemci - Şifreleme Servisi")
        self.window.geometry("800x750")
        self.window.configure(bg="#f0f0f0")
        
        self.crypto = CryptoFunctions()
        self.client_socket = None
        self.is_connected = False
        
        self.create_ui()
        self.connect_to_server()
        
    def create_ui(self):
        # Başlık
        header = tk.Frame(self.window, bg="#2196F3", height=80)
        header.pack(fill=tk.X)
        
        tk.Label(header, text="🔒 İSTEMCİ - Şifreleme Servisi", 
                 font=("Arial", 20, "bold"), bg="#2196F3", fg="white").pack(pady=20)
        
        # Ana içerik
        content = tk.Frame(self.window, bg="white")
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Durum Bilgisi
        status_frame = tk.LabelFrame(content, text="📡 Bağlantı Durumu", 
                                     font=("Arial", 11, "bold"), bg="white", fg="#2196F3")
        status_frame.pack(fill=tk.X, pady=10)
        
        self.status_label = tk.Label(status_frame, text="⏳ Sunucuya bağlanılıyor...", 
                                      font=("Arial", 10), bg="white", fg="orange")
        self.status_label.pack(pady=10)
        
        # Şifreleme Yöntemi
        tk.Label(content, text="🔐 Şifreleme Yöntemi", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        
        self.cipher_var = tk.StringVar()
        cipher_combo = ttk.Combobox(content, textvariable=self.cipher_var,
                                       font=("Arial", 11), width=50, state="readonly")
        cipher_combo['values'] = ("Columnar Transposition (Anahtar Kelime)", "Caesar Cipher (Kaydırma)", 
                                     "Substitution Cipher", "Vigenere Cipher", "Playfair Cipher", 
                                     "Route Cipher", "Rail Fence Cipher (Ray Sayısı)", "Hash (MD5)")
        cipher_combo.current(0)
        cipher_combo.pack(pady=5)
        
        # Anahtar
        tk.Label(content, text="🔑 Anahtar", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.key_entry = tk.Entry(content, font=("Arial", 11), width=52)
        # Başlangıçta Columnar için anahtarı ayarla
        self.key_entry.insert(0, "TRUVA") 
        self.key_entry.pack(pady=5)
        
        # ComboBox'a event bağla
        cipher_combo.bind("<<ComboboxSelected>>", self.update_key_field)
        
        # Mesaj
        tk.Label(content, text="💬 Mesaj", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.msg_text = tk.Text(content, font=("Arial", 11), height=5, width=65, wrap=tk.WORD)
        self.msg_text.pack(pady=5)
        
        # Butonlar
        btn_frame = tk.Frame(content, bg="white")
        btn_frame.pack(pady=15)
        
        tk.Button(btn_frame, text="🔒 Şifrele", command=self.encrypt,
                   bg="#2196F3", fg="white", font=("Arial", 11, "bold"),
                   padx=30, pady=10, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="📤 Sunucuya Gönder", command=self.send_to_server,
                   bg="#4CAF50", fg="white", font=("Arial", 11, "bold"),
                   padx=30, pady=10, relief=tk.FLAT, cursor="hand2").pack(side=tk.LEFT, padx=5)
        
        # Şifrelenmiş Mesaj
        tk.Label(content, text="🔐 Şifrelenmiş Mesaj", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.encrypted_text = tk.Text(content, font=("Courier", 10), 
                                      height=5, width=65, wrap=tk.WORD, bg="#e3f2fd")
        self.encrypted_text.pack(pady=5)
        
        # Sunucudan Gelen Cevap
        tk.Label(content, text="✅ Sunucudan Gelen Deşifrelenmiş Mesaj", 
                 font=("Arial", 11, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.response_text = tk.Text(content, font=("Courier", 10), 
                                     height=5, width=65, wrap=tk.WORD, bg="#e8f5e9")
        self.response_text.pack(pady=5)
        
        # Log Alanı
        tk.Label(content, text="📋 İşlem Logları", 
                 font=("Arial", 10, "bold"), bg="white", fg="#555").pack(anchor=tk.W, pady=(10,5))
        self.log_text = scrolledtext.ScrolledText(content, font=("Courier", 9), 
                                                  height=4, wrap=tk.WORD, bg="#f5f5f5")
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
    def update_key_field(self, event):
        """Seçilen şifreye göre anahtar giriş alanını ayarlar."""
        selected_cipher = self.cipher_var.get()
        self.key_entry.config(state=tk.NORMAL, fg="black")
        self.key_entry.delete(0, tk.END)

        if "Hash" in selected_cipher:
            self.key_entry.insert(0, "MD5 için anahtar gerekmez.")
            self.key_entry.config(state=tk.DISABLED, fg="#888")
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
        elif "Route" in selected_cipher:
            self.key_entry.insert(0, "4 (Sütun Sayısı)")
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
        
        if "Hash" not in cipher and not key:
            messagebox.showerror("Hata", "Lütfen bir anahtar girin!")
            return
        
        if "Hash" in cipher:
            key = ""
        
        try:
            if "Columnar" in cipher:
                encrypted = self.crypto.columnar_encrypt(msg, key)
            elif "Caesar" in cipher:
                encrypted = self.crypto.caesar_encrypt(msg, int(key))
            elif "Substitution" in cipher:
                encrypted = self.crypto.substitution_encrypt(msg, key)
            elif "Vigenere" in cipher:
                encrypted = self.crypto.vigenere_encrypt(msg, key)
            elif "Playfair" in cipher:
                encrypted = self.crypto.playfair_encrypt(msg, key)
            elif "Route" in cipher:
                encrypted = self.crypto.route_encrypt(msg, key)
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
            # JSON formatında gönder
            request = json.dumps({
                'cipher': cipher,
                'key': key if "Hash" not in cipher else "", 
                'message': encrypted_msg
            })
            
            self.client_socket.send(request.encode('utf-8'))
            self.log(f"📤 Şifreli mesaj sunucuya gönderildi")
            
            # Cevap bekle
            response = self.client_socket.recv(4096).decode('utf-8')
            data = json.loads(response)
            
            if data.get('status') == 'success':
                decrypted = data.get('decrypted')
                self.response_text.delete("1.0", tk.END)
                self.response_text.insert("1.0", decrypted)
                self.log(f"✅ Sunucudan deşifrelenmiş mesaj alındı")
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