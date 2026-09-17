import os
from cryptography.fernet import Fernet

KEY_FILE = "master.key"

def load_or_generate_key() -> bytes:
    """Khởi tạo hoặc đọc khóa mã hóa chính (Master Key)"""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    with open(KEY_FILE, "rb") as f:
        return f.read()

def encrypt_secret(plain_text: str) -> str:
    """Mã hóa chuỗi secret sang ciphertext"""
    key = load_or_generate_key()
    fernet = Fernet(key)
    return fernet.encrypt(plain_text.encode("utf-8")).decode("utf-8")

def decrypt_secret(cipher_text: str) -> str:
    """Giải mã ciphertext trở về plaintext trong bộ nhớ RAM"""
    key = load_or_generate_key()
    fernet = Fernet(key)
    return fernet.decrypt(cipher_text.encode("utf-8")).decode("utf-8")

if __name__ == "__main__":
    demo_secret = "mongodb://admin:SuperSecret2026@localhost:27017"
    encrypted = encrypt_secret(demo_secret)
    decrypted = decrypt_secret(encrypted)

    print("--- KIỂM THỬ MÃ HÓA FERNET ---")
    print(f"Bản rõ:    {demo_secret}")
    print(f"Bản mã:    {encrypted}")
    print(f"Giải mã:   {decrypted}")