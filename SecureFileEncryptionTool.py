import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import threading
from tkinter import ttk

# Key derivation function
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encryption function
def encrypt_file(filepath, password, progress_var, status_label):
    try:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        with open(filepath, "rb") as f:
            plaintext = f.read()

        padding_length = 16 - (len(plaintext) % 16)
        plaintext += bytes([padding_length] * padding_length)

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        encrypted_data = salt + iv + ciphertext

        with open(filepath + ".enc", "wb") as f:
            f.write(encrypted_data)

        progress_var.set(100)
        status_label.config(text="Encryption Successful!", fg="green")
    except Exception as e:
        status_label.config(text=f"Error: {str(e)}", fg="red")

# Decryption function
def decrypt_file(filepath, password, progress_var, status_label):
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        salt, iv, ciphertext = data[:16], data[16:32], data[32:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = plaintext_padded[-1]
        plaintext = plaintext_padded[:-padding_length]

        output_filepath = filepath.replace(".enc", "_decrypted")
        with open(output_filepath, "wb") as f:
            f.write(plaintext)

        progress_var.set(100)
        status_label.config(text="Decryption Successful!", fg="green")
    except Exception as e:
        status_label.config(text=f"Error: {str(e)}", fg="red")

# GUI Implementation
def browse_file(entry):
    filename = filedialog.askopenfilename()
    entry.delete(0, tk.END)
    entry.insert(0, filename)

def toggle_password_visibility(entry, button):
    if entry.cget('show') == '*':
        entry.config(show='')
        button.config(text='Hide')
    else:
        entry.config(show='*')
        button.config(text='View')

def start_encryption(entry, password_entry, progress_var, status_label):
    filepath = entry.get()
    password = password_entry.get()
    
    if not filepath or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return
    
    progress_var.set(0)
    status_label.config(text="Encrypting...", fg="blue")
    
    threading.Thread(target=encrypt_file, args=(filepath, password, progress_var, status_label)).start()

def start_decryption(entry, password_entry, progress_var, status_label):
    filepath = entry.get()
    password = password_entry.get()
    
    if not filepath or not password:
        messagebox.showwarning("Warning", "Please select a file and enter a password.")
        return
    
    progress_var.set(0)
    status_label.config(text="Decrypting...", fg="blue")
    
    threading.Thread(target=decrypt_file, args=(filepath, password, progress_var, status_label)).start()

# GUI Setup
root = tk.Tk()
root.title("Secure File Encryption Tool")
root.geometry("400x350")

file_frame = tk.Frame(root)
file_frame.pack(pady=10)

file_entry = tk.Entry(file_frame, width=30)
file_entry.pack(side=tk.LEFT, padx=5)

browse_button = tk.Button(file_frame, text="Browse", command=lambda: browse_file(file_entry), bd=4, highlightthickness=4)
browse_button.pack(side=tk.RIGHT)

password_frame = tk.Frame(root)
password_frame.pack(pady=10)

password_entry = tk.Entry(password_frame, width=35, show="*")
password_entry.pack(side=tk.LEFT)

view_button = tk.Button(password_frame, text="View", command=lambda: toggle_password_visibility(password_entry, view_button), bd=4, highlightthickness=4)
view_button.pack(side=tk.RIGHT, padx=5)

encrypt_button = tk.Button(root, text="Encrypt File", command=lambda: start_encryption(file_entry, password_entry, progress_var, status_label), bd=4, highlightthickness=4)
encrypt_button.pack(pady=5)

decrypt_button = tk.Button(root, text="Decrypt File", command=lambda: start_decryption(file_entry, password_entry, progress_var, status_label), bd=4, highlightthickness=4)
decrypt_button.pack(pady=5)

progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(root, variable=progress_var, maximum=100)
progress_bar.pack(pady=10, fill=tk.X)

status_label = tk.Label(root, text="", fg="black")
status_label.pack()

root.mainloop()
