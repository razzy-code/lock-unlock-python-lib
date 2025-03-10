import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from Crypto.Cipher import AES
import hashlib
import os
import threading
import psutil
import time
import random
import string

BLOCK_SIZE = 16
MAX_RAM_USAGE = 4 * 1024 * 1024 * 1024  # 4 GB
MAX_DISK_SPEED = 500 * 1024 * 1024  # 500 MB/s

def generate_pass_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))

pass_key = generate_pass_key()
key = hashlib.sha256(pass_key.encode()).digest()

def pad(data):
    return data + (BLOCK_SIZE - len(data) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(data) % BLOCK_SIZE).encode()

def log_message(message, log_widget):
    log_widget.insert(tk.END, message + '\n')
    log_widget.yview(tk.END)

def check_ram_usage():    
    while psutil.virtual_memory().available < MAX_RAM_USAGE:
        time.sleep(1)

def check_disk_speed(data_size, start_time):    
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        speed = data_size / elapsed_time
        if speed > MAX_DISK_SPEED:
            time.sleep(0.1)

def encrypt_file(input_folder, output_file, log_widget):
    try:
        log_message("Arşiv oluşturuluyor...", log_widget)
        shutil.make_archive("lock_data", 'zip', input_folder)
        with open("lock_data.zip", "rb") as f:
            raw_data = f.read()
        os.remove("lock_data.zip")        
        cipher = AES.new(key, AES.MODE_CBC)
        encrypted_data = cipher.iv + cipher.encrypt(pad(raw_data))        
        check_ram_usage()       
        start_time = time.time()
        block_size = 1024 * 1024 * 1024
        with open(output_file, "wb") as f:
            total_written = 0
            while total_written < len(encrypted_data):                
                chunk = encrypted_data[total_written:total_written + block_size]
                f.write(chunk)
                total_written += len(chunk)        
                check_disk_speed(total_written, start_time)

        with open("pass.key", "w") as f:
            f.write(pass_key)
        
        log_message(f"{output_file} başarıyla oluşturuldu!", log_widget)
        messagebox.showinfo("Başarılı", f"{output_file} başarıyla oluşturuldu!\nŞifre: {pass_key}")
    except Exception as e:
        log_message(f"Hata: {str(e)}", log_widget)
        messagebox.showerror("Hata", f"Şifreleme hatası: {str(e)}")

def select_folder(log_widget):
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        output_file = os.path.join(os.getcwd(), "lock_data.lock")
        threading.Thread(target=encrypt_file, args=(folder_selected, output_file, log_widget), daemon=True).start()

root = tk.Tk()
root.title("Locker")
root.geometry("500x400")
log_widget = scrolledtext.ScrolledText(root, width=60, height=15)
log_widget.pack(pady=10)
btn_select_folder = tk.Button(root, text="Şifreleme İşlemini Başlat", command=lambda: select_folder(log_widget))
btn_select_folder.pack(pady=20)
root.mainloop()