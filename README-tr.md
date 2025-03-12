# Lock-Unlock-Python-Lib 

## 🛠️Sürüm 1.6.530

Lock-Unlock-Python-Lib, AES şifrelemesini kullanarak klasörleri şifreleyen ve şifresini çözen bir Python kütüphanesidir.
Dosyalarınızı güvence altına almak ve gerektiğinde geri almak için basit bir yol sağlar.

## 📌 Özellikler

- Tüm klasörleri güvenli bir `.lock` dosyasına şifreler.
- Şifreleme için rastgele 16 karakterli bir parola oluşturur.
- Güçlü güvenlik için AES (CBC modu) şifrelemesini kullanır.
- Şifreleme sırasında bellek ve disk kullanımını otomatik olarak yönetir.
- `.lock` dosyalarını orijinal klasör yapılarına geri şifresini çözer.

## 🔧 Kurulum

Kitaplığı pip kullanarak kurabilirsiniz:

```
pip install lock-unlock-python-lib
```

### 🚀 Kullanım

Bir Klasörü Şifrele

```
from lock_unlock_lib import encrypt_folder

encrypt_folder("my_folder", "encrypted_data.lock")
```

Bu, şifrelenmiş bir .lock dosyası ve şifreleme anahtarını içeren bir pass.key dosyası oluşturacaktır.

Bir Klasörün Şifresini Çöz

```
from lock_unlock_lib import decrypt_file

decrypt_file("encrypted_data.lock", "pass.key")
```

Bu, klasörü şifrelenmiş dosyadan geri yükler.

### 🛠 Gereksinimler

- Python 3.7+

```
pip install -r req.txt
```

### 📜 Lisans

Bu proje MIT Lisansı altında lisanslanmıştır - ayrıntılar için LİSANS dosyasına bakın.

### 🤝 Katkıda Bulunma

[GitHub](https://github.com/razzy-code/lock-unlock-python-lib) ve [Website](https://razzy-code.glitch.me/) üzerinden sorun veya çekme isteği göndererek katkıda bulunmaktan çekinmeyin
