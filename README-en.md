# Lock-Unlock-Python-Lib

Lock-Unlock-Python-Lib is a Python library that encrypts and decrypts folders using AES encryption.
It provides a simple way to secure your files and retrieve them whenever needed.

## 📌 Features

- Encrypts entire folders into a secure `.lock` file.
- Generates a random 16-character password for encryption.
- Uses AES (CBC mode) encryption for strong security.
- Automatically manages memory and disk usage during encryption.
- Decrypts `.lock` files back into their original folder structure.

## 🔧 Installation

You can install the library using pip:

```
pip install lock-unlock-python-lib
```

### 🚀 Usage

Encrypt a Folder

```
from lock_unlock_lib import encrypt_folder

encrypt_folder("my_folder", "encrypted_data.lock")
```

This will create an encrypted .lock file and a pass.key file containing the encryption key.

Decrypt a Folder

```
from lock_unlock_lib import decrypt_file

decrypt_file("encrypted_data.lock", "pass.key")
```

This restores the folder from the encrypted file.

### 🛠 Requirements

- Python 3.7+

```
pip install -r req.txt
```

### 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

### 🤝 Contributing

Feel free to contribute by submitting issues or pull requests on [GitHub](https://github.com/razzy-code/lock-unlock-python-lib) and [Website](https://razzy-code.glitch.me/)
