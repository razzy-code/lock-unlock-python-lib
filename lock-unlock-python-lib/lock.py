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
import webbrowser
import requests
from PIL import Image, ImageTk
import io
import logging

BLOCK_SIZE = 16
MAX_RAM_USAGE = 4 * 1024 * 1024 * 1024
MAX_DISK_SPEED = 500 * 1024 * 1024

logging.basicConfig(
    filename='locker.log', 
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

def generate_pass_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))
pass_key = generate_pass_key()
key = hashlib.sha256(pass_key.encode()).digest()

def pad(data):
    return data + (BLOCK_SIZE - len(data) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(data) % BLOCK_SIZE).encode()

def log_message(message, log_widget, color="black"):
    log_widget.insert(tk.END, message + '\n', color)
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

def get_folder_size(folder_path):
    total_size = 0
    file_list = []
    for dirpath, dirnames, filenames in os.walk(folder_path):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            file_size = os.path.getsize(filepath)
            total_size += file_size
            file_list.append(f"{filepath} ({file_size} byte)")
    return total_size, file_list

def format_size(size_in_bytes):
    if size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"

def encrypt_file(input_folder, output_file, log_widget, btn_select_folder, stats_label):
    try:
        folder_size, file_list = get_folder_size(input_folder)
        formatted_size = format_size(folder_size)
        log_message(f"Arşiv oluşturuluyor... Klasör: {input_folder}, Boyut: {formatted_size}", log_widget, color="blue")
        log_to_file("BİLGİ - ", f"Arşiv oluşturuluyor... Klasör: {input_folder}, Boyut: {formatted_size}")
        shutil.make_archive("locked_data", 'zip', input_folder)
        with open("locked_data.zip", "rb") as f:
            raw_data = f.read()
        os.remove("locked_data.zip")        
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
        log_message(f"{output_file} başarıyla oluşturuldu!", log_widget, color="green")
        log_to_file("BİLGİ - ", f"{output_file} başarıyla oluşturuldu!")
        messagebox.showinfo("Başarılı", f"{output_file} başarıyla oluşturuldu!\nŞifre: {pass_key}")
    except Exception as e:
        log_message(f"Hata: {str(e)}", log_widget, color="red")
        log_to_file("HATA - ", f"Şifreleme hatası: {str(e)}")
        messagebox.showerror("Hata", f"Şifreleme hatası: {str(e)}")

def select_folder(log_widget, btn_select_folder, stats_label):
    folder_selected = filedialog.askdirectory()
    if folder_selected:
        btn_select_folder.config(state=tk.DISABLED, text="Lütfen Bekleyiniz...")
        output_file = os.path.join(os.getcwd(), "locked_data.lock")
        threading.Thread(target=encrypt_file, args=(folder_selected, output_file, log_widget, btn_select_folder, stats_label), daemon=True).start()

def internet_check():
    try:
        response = requests.get("https://www.google.com", timeout=5)
        return True
    except requests.ConnectionError:
        return False

def about_window():
    about_win = tk.Toplevel(root)
    about_win.title("Locker - Hakkında")
    about_win.geometry("400x300")
    about_win.iconbitmap("lock.ico")
    about_win.config(bg="#2c3e50")
    if internet_check():
        img_url = "https://cdn.glitch.global/c481494a-136a-4e6f-bf28-97c9b2f2851e/lock.ico?v=1741715697154"
        img_data = requests.get(img_url).content
        img = Image.open(io.BytesIO(img_data))
        img = img.resize((100, 100))
        img = ImageTk.PhotoImage(img)
        label_img = tk.Label(about_win, image=img, bg="#2c3e50")
        label_img.image = img
        label_img.pack(pady=10)
    label_about = tk.Label(about_win, text="Uygulama: Locker\nYapımcı: razzy-code\nSürüm: 1.6.530\nLisans: MIT License", font=("Helvetica", 12), bg="#2c3e50", fg="white")
    label_about.pack(pady=10)
    label_github = tk.Label(about_win, text="GitHub", fg="blue", bg="#2c3e50", cursor="hand2")
    label_github.pack()
    label_github.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/razzy-code/lock-unlock-python-lib"))
    label_website = tk.Label(about_win, text="Website", fg="blue", bg="#2c3e50", cursor="hand2")
    label_website.pack()
    label_website.bind("<Button-1>", lambda e: webbrowser.open("https://razzy-code.glitch.me/"))

def system_info(start_time=None, start_disk_read=None, start_disk_write=None):
    process = psutil.Process(os.getpid())
    cpu = process.cpu_percent(interval=1)
    ram = process.memory_info().rss / (1024 * 1024)
    if start_time is None:
        start_time = time.time()
        disk = psutil.disk_io_counters()
        start_disk_read = disk.read_bytes
        start_disk_write = disk.write_bytes
        return cpu, ram, 0, 0, start_time, start_disk_read, start_disk_write
    disk = psutil.disk_io_counters()
    elapsed_time = time.time() - start_time
    disk_read = (disk.read_bytes - start_disk_read) / (1024 * 1024)  
    disk_write = (disk.write_bytes - start_disk_write) / (1024 * 1024) 
    disk_read_speed = disk_read / elapsed_time if elapsed_time > 0 else 0
    disk_write_speed = disk_write / elapsed_time if elapsed_time > 0 else 0
    return cpu, ram, disk_write_speed, disk_read_speed, start_time, start_disk_read, start_disk_write

def update_system_stats(stats_label):
    start_time = None
    start_disk_read = start_disk_write = 0
    while True:
        cpu, ram, disk_write_speed, disk_read_speed, start_time, start_disk_read, start_disk_write = system_info(start_time, start_disk_read, start_disk_write)
        stats_label.config(text=f"CPU: {cpu}% | RAM: {ram:.2f} MB | Disk Yazma: {disk_write_speed:.2f} MB/s | Disk Okuma: {disk_read_speed:.2f} MB/s")
        time.sleep(1)

def start_system_stats_thread(stats_label):
    threading.Thread(target=update_system_stats, args=(stats_label,), daemon=True).start()
root = tk.Tk()
root.title("Locker")
root.geometry("800x600")
root.config(bg="#2c3e50")
root.iconbitmap("lock.ico")
log_widget = scrolledtext.ScrolledText(root, width=70, height=15)
log_widget.pack(pady=10)
log_widget.tag_configure("blue", foreground="blue")
log_widget.tag_configure("green", foreground="green")
log_widget.tag_configure("red", foreground="red")
log_widget.tag_configure("black", foreground="black")
btn_select_folder = tk.Button(root, text="Başlat", command=lambda: select_folder(log_widget, btn_select_folder, stats_label))
btn_select_folder.pack(pady=20)
stats_label = tk.Label(root, text="CPU: 0% | RAM: 0 MB | Disk Hızı: 0 MB/s", font=("Helvetica", 10), bg="#2c3e50", fg="white")
stats_label.pack(pady=10)
footer_label = tk.Label(root, text="NOT: Bu programın sağlıklı çalışabilmesi için bilgisayarınızın en az 4 GB RAM ve en az 500 MB/s Yazma/Okuma hızına sahip olması gerekir.", fg="red", font=("Helvetica", 8), bg="#2c3e50")
footer_label.pack(side=tk.BOTTOM, pady=5)
btn_about = tk.Button(root, text="Hakkında", command=about_window)
btn_about.pack(pady=10)
start_system_stats_thread(stats_label)
root.mainloop()
