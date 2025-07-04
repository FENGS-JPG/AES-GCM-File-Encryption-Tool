import tkinter as tk
from tkinter import filedialog, messagebox
from encryptor import encrypt_file, decrypt_file

DEFAULT_PASSWORD = "default-123"

def choose_file():
    path = filedialog.askopenfilename()
    if path:
        file_path.set(path)

def encrypt_action():
    path = file_path.get()
    if not path:
        messagebox.showerror("错误", "请选择文件")
        return
    encrypt_file(path, DEFAULT_PASSWORD)
    messagebox.showinfo("成功", f"已加密: {path}.enc")

def decrypt_action():
    path = file_path.get()
    if not path:
        messagebox.showerror("错误", "请选择文件")
        return
    decrypt_file(path, DEFAULT_PASSWORD)
    dec_path = path.replace(".enc", ".dec")
    messagebox.showinfo("成功", f"已解密: {dec_path}")

root = tk.Tk()
root.title("AES-GCM 文件加密器")

file_path = tk.StringVar()

tk.Label(root, text="文件路径:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
tk.Entry(root, textvariable=file_path, width=40).grid(row=0, column=1, padx=5, pady=5)
tk.Button(root, text="选择文件", command=choose_file).grid(row=0, column=2, padx=5)

tk.Button(root, text="加密文件", command=encrypt_action, bg="#4CAF50", fg="white", width=15).grid(row=1, column=1, pady=10, sticky="w")
tk.Button(root, text="解密文件", command=decrypt_action, bg="#2196F3", fg="white", width=15).grid(row=1, column=1, pady=10, sticky="e")

root.mainloop()
