import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets
import logging

# Setup logging
logging.basicConfig(
    filename="securevault.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# Key derivation function for AES
def derive_key(passphrase, salt):
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(passphrase.encode())

# AES Encryption
def encrypt_with_aes(input_file, output_file, passphrase):
    try:
        salt = secrets.token_bytes(16)
        key = derive_key(passphrase, salt)

        with open(input_file, "rb") as f:
            data = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(output_file, "wb") as f:
            f.write(salt + iv + encrypted_data)

        logging.info(f"AES encryption successful: {input_file} -> {output_file}")
        messagebox.showinfo("Success", f"File encrypted and saved to {output_file}")
    except Exception as e:
        logging.error(f"AES encryption failed: {e}")
        messagebox.showerror("Error", str(e))

# AES Decryption
def decrypt_with_aes(input_file, output_file, passphrase):
    try:
        with open(input_file, "rb") as f:
            data = f.read()

        salt = data[:16]
        iv = data[16:32]
        encrypted_data = data[32:]

        key = derive_key(passphrase, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        logging.info(f"AES decryption successful: {input_file} -> {output_file}")
        messagebox.showinfo("Success", f"File decrypted and saved to {output_file}")
    except Exception as e:
        logging.error(f"AES decryption failed: {e}")
        messagebox.showerror("Error", str(e))

# GUI Functions
def validate_passphrase(passphrase, confirmation):
    """Validate the passphrase and confirmation."""
    if len(passphrase) < 8:
        messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
        return False
    if passphrase != confirmation:
        messagebox.showerror("Error", "Passphrases do not match. Please try again.")
        return False
    return True

def encrypt_action():
    method = encryption_method.get()
    input_file = filedialog.askopenfilename(title="Select file to encrypt")
    if not input_file:
        return

    output_file = filedialog.asksaveasfilename(title="Save encrypted file", defaultextension=".enc")
    if not output_file:
        return

    passphrase = passphrase_entry.get()
    confirmation = confirm_passphrase_entry.get()

    if not validate_passphrase(passphrase, confirmation):
        return

    if method == "AES":
        encrypt_with_aes(input_file, output_file, passphrase)

def decrypt_action():
    method = encryption_method.get()
    input_file = filedialog.askopenfilename(title="Select file to decrypt")
    if not input_file:
        return

    output_file = filedialog.asksaveasfilename(title="Save decrypted file")
    if not output_file:
        return

    passphrase = passphrase_entry.get()
    if len(passphrase) < 8:
        messagebox.showerror("Error", "Passphrase must be at least 8 characters long.")
        return

    if method == "AES":
        decrypt_with_aes(input_file, output_file, passphrase)

def quit_app():
    app.destroy()

# GUI Setup
app = tk.Tk()
app.title("SecureVault GUI")
app.geometry("400x350")

# Title
tk.Label(app, text="SecureVault - File Encryption and Decryption", font=("Arial", 14)).pack(pady=10)

# Encryption Method Dropdown
encryption_method = tk.StringVar(value="AES")
tk.Label(app, text="Encryption Method:").pack(pady=5)
tk.OptionMenu(app, encryption_method, "AES", "ChaCha20", "RSA").pack()

# Passphrase Input
tk.Label(app, text="Passphrase:").pack(pady=5)
passphrase_entry = tk.Entry(app, show="*", width=40)
passphrase_entry.pack()

# Passphrase Confirmation Input
tk.Label(app, text="Confirm Passphrase:").pack(pady=5)
confirm_passphrase_entry = tk.Entry(app, show="*", width=40)
confirm_passphrase_entry.pack()

# Action Buttons
tk.Button(app, text="Encrypt File", command=encrypt_action, width=20).pack(pady=10)
tk.Button(app, text="Decrypt File", command=decrypt_action, width=20).pack(pady=10)
tk.Button(app, text="Quit", command=quit_app, width=20).pack(pady=10)

app.mainloop()