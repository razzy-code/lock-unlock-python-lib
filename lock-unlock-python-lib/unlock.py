import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from Crypto.Cipher import AES
import hashlib
import threading
import psutil
import time
import logging
import requests
import io
from PIL import Image, ImageTk
import webbrowser

logging.basicConfig(
    filename='unlocker.log', 
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'
)

def log_to_file(level, message):
    if level == "BİLGİ - ":
        logging.info(message)
    elif level == "UYARI - ":
        logging.warning(message)
    elif level == "HATA - ":
        logging.error(message)

def log_message(message, log_widget):
    log_widget.insert(tk.END, message + '\n')
    log_widget.yview(tk.END)  

MAX_RAM_USAGE = 4 * 1024 * 1024 * 1024
MAX_DISK_SPEED = 500 * 1024 * 1024 

def check_ram_usage():
    while psutil.virtual_memory().available < MAX_RAM_USAGE:
        time.sleep(1)

def check_disk_speed(data_size, start_time):    
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        speed = data_size / elapsed_time
        if speed > MAX_DISK_SPEED:
            time.sleep(0.1)

def internet_check():
    try:
        response = requests.get("https://www.google.com", timeout=5)
        return True
    except requests.ConnectionError:
        return False

def about_window():
    about_win = tk.Toplevel(root)
    about_win.title("Unlocker - Hakkında")
    about_win.geometry("400x300")
    about_win.iconbitmap("unlock.ico")
    about_win.config(bg="#2c3e50")
    if internet_check():
        img_url = "https://cdn.glitch.global/c481494a-136a-4e6f-bf28-97c9b2f2851e/unlock.ico?v=1741719073161"
        img_data = requests.get(img_url).content
        img = Image.open(io.BytesIO(img_data))
        img = img.resize((100, 100))
        img = ImageTk.PhotoImage(img)
        label_img = tk.Label(about_win, image=img, bg="#2c3e50")
        label_img.image = img
        label_img.pack(pady=10)
    label_about = tk.Label(about_win, text="Uygulama: Unlocker\nYapımcı: razzy-code\nSürüm: 1.6.530\nLisans: MIT License", font=("Helvetica", 12), bg="#2c3e50", fg="white")
    label_about.pack(pady=10)
    label_github = tk.Label(about_win, text="GitHub", fg="blue", bg="#2c3e50", cursor="hand2")
    label_github.pack()
    label_github.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/razzy-code/lock-unlock-python-lib"))
    label_website = tk.Label(about_win, text="Website", fg="blue", bg="#2c3e50", cursor="hand2")
    label_website.pack()
    label_website.bind("<Button-1>", lambda e: webbrowser.open("https://razzy-code.glitch.me/"))

def unpad(data):
    return data[:-data[-1]]

def decrypt_file(lock_file, pass_key_file, log_widget, btn_select_files):
    try:
        log_message("Şifre çözme işlemi başlatılıyor...", log_widget)
        btn_select_files.config(state=tk.DISABLED, text="Lütfen Bekleyiniz...")
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
        temp_zip = "unlocked_data.zip"
        with open(temp_zip, "wb") as f:
            f.write(decrypted_data)        
        output_folder = os.path.join("unlocked_data", os.path.splitext(os.path.basename(lock_file))[0])
        os.makedirs(output_folder, exist_ok=True)
        shutil.unpack_archive(temp_zip, output_folder)
        os.remove(temp_zip)
        log_message(f"{output_folder} klasörüne başarıyla çıkarıldı!", log_widget)
        messagebox.showinfo("Başarılı", f"{output_folder} klasörüne başarıyla çıkarıldı!")
    except Exception as e:
        log_message(f"Hata: {str(e)}", log_widget)
        messagebox.showerror("Hata", f"Şifre çözme hatası: {str(e)}")
    finally:
        btn_select_files.config(state=tk.NORMAL, text="Çözümleme İşlemini Başlat")

def select_files(log_widget, btn_select_files):
    pass_key_file = filedialog.askopenfilename(title="Şifre Dosyasını Seç (.key)", filetypes=[("Anahtar Dosyası", "*.key")])
    if not pass_key_file:
        return
    lock_file = filedialog.askopenfilename(title="Şifreli Dosyayı Seç (.lock)", filetypes=[("Şifrelenmiş Dosya", "*.lock")])
    if not lock_file:
        return
    threading.Thread(target=decrypt_file, args=(lock_file, pass_key_file, log_widget, btn_select_files), daemon=True).start()
def footer_label_widget(root):
    footer_label = tk.Label(root, text="NOT: Bu programın sağlıklı çalışabilmesi için bilgisayarınızın en az 4 GB RAM ve en az 500 MB/s Yazma/Okuma hızına sahip olması gerekir.", fg="red", font=("Helvetica", 8), bg="#2c3e50")
    footer_label.pack(side=tk.BOTTOM, pady=5)

root = tk.Tk()
root.title("Unlocker")
root.geometry("800x600")
root.config(bg="#2c3e50")
root.iconbitmap("unlock.ico")
log_widget = scrolledtext.ScrolledText(root, width=70, height=15)
log_widget.pack(pady=10)
log_widget.tag_configure("blue", foreground="blue")
log_widget.tag_configure("green", foreground="green")
log_widget.tag_configure("red", foreground="red")
log_widget.tag_configure("black", foreground="black") 
btn_select_files = tk.Button(root, text="Çözümleme İşlemini Başlat", command=lambda: select_files(log_widget, btn_select_files))
btn_select_files.pack(pady=20)
btn_about = tk.Button(root, text="Hakkında", command=about_window)
btn_about.pack()
footer_label_widget(root)
root.mainloop()
