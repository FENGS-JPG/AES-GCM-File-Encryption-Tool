import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from utils import derive_key

def encrypt_file(filepath: str, password: str) -> None:
    if not os.path.isfile(filepath):
        print(f"[!] 文件不存在: {filepath}")
        return
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"[!] 无法读取文件: {filepath} - {e}")
        return
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        encrypted = aesgcm.encrypt(nonce, data, None)
    except Exception as e:
        print(f"[!] 加密失败: {e}")
        return
    enc_path = filepath + ".enc"
    try:
        with open(enc_path, "wb") as f:
            f.write(salt + nonce + encrypted)
        print(f"[+] 加密成功: {enc_path}")
    except Exception as e:
        print(f"[!] 写入加密文件失败: {e}")

def decrypt_file(enc_path: str, password: str) -> None:
    if not os.path.isfile(enc_path):
        print(f"[!] 加密文件不存在: {enc_path}")
        return
    try:
        with open(enc_path, "rb") as f:
            raw = f.read()
    except Exception as e:
        print(f"[!] 无法读取加密文件: {e}")
        return
    if len(raw) < 28:
        print("[!] 加密文件结构异常，太短")
        return
    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        print(f"[!] 解密失败，可能密码错误或文件被篡改: {e}")
        return
    dec_path = enc_path.replace(".enc", ".dec")
    try:
        with open(dec_path, "wb") as f:
            f.write(decrypted)
        print(f"[+] 解密成功: {dec_path}")
    except Exception as e:
        print(f"[!] 写入解密文件失败: {e}")

def encrypt_directory(directory: str, password: str, recursive: bool = True, extensions: list = None):
    if not os.path.isdir(directory):
        print(f"[!] 路径不是目录: {directory}")
        return
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if filepath.endswith(".enc"):
                continue
            if extensions and not any(filepath.lower().endswith(ext) for ext in extensions):
                continue
            encrypt_file(filepath, password)
        if not recursive:
            break
