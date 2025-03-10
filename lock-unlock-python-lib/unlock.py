import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from Crypto.Cipher import AES
import hashlib
import threading
import psutil
import time

def unpad(data):
    return data[:-data[-1]]

MAX_RAM_USAGE = 4 * 1024 * 1024 * 1024

def check_ram_usage():
    while psutil.virtual_memory().available < MAX_RAM_USAGE:
        time.sleep(1)

def log_message(message, log_widget):
    log_widget.insert(tk.END, message + '\n')
    log_widget.yview(tk.END)  

def decrypt_file(lock_file, pass_key_file, log_widget):
    try:
        log_message("Şifre çözme işlemi başlatılıyor...", log_widget)
        check_ram_usage()       
        with open(pass_key_file, "r") as f:
            pass_key = f.read().strip()        
        key = hashlib.sha256(pass_key.encode()).digest()      
        with open(lock_file, "rb") as f:
            encrypted_data = f.read()
        iv = encrypted_data[:16]  
        encrypted_content = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_content))        
        temp_zip = "unlock_data.zip"
        with open(temp_zip, "wb") as f:
            f.write(decrypted_data)        
        output_folder = os.path.join("out", os.path.splitext(os.path.basename(lock_file))[0])
        os.makedirs(output_folder, exist_ok=True)
        shutil.unpack_archive(temp_zip, output_folder)
        os.remove(temp_zip)
        log_message(f"{output_folder} klasörüne başarıyla çıkarıldı!", log_widget)
        messagebox.showinfo("Başarılı", f"{output_folder} klasörüne başarıyla çıkarıldı!")
    except Exception as e:
        log_message(f"Hata: {str(e)}", log_widget)
        messagebox.showerror("Hata", f"Şifreleme çözme hatası: {str(e)}")

def select_files(log_widget):
    pass_key_file = filedialog.askopenfilename(title="Şifre Dosyasını Seç (.key)", filetypes=[("Anahtar Dosyası", "*.key")])
    if not pass_key_file:
        return

    lock_file = filedialog.askopenfilename(title="Şifreli Dosyayı Seç (.lock)", filetypes=[("Şifrelenmiş Dosya", "*.lock")])
    if not lock_file:
        return

    threading.Thread(target=decrypt_file, args=(lock_file, pass_key_file, log_widget), daemon=True).start()

root = tk.Tk()
root.title("Unlocker")
root.geometry("500x400")
log_widget = scrolledtext.ScrolledText(root, width=60, height=15)
log_widget.pack(pady=10)
btn_select_files = tk.Button(root, text="Çözümleme İşlemini Başlat", command=lambda: select_files(log_widget))
btn_select_files.pack(pady=20)
root.mainloop()