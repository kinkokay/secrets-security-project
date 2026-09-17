import os
import sqlite3
from cryptography.fernet import Fernet

DB_PATH = "secrets_storage.db"
KEY_FILE = "master.key"

class SecureStorage:
    def __init__(self):
        self.master_key = self._get_or_create_master_key()
        self.cipher = Fernet(self.master_key)
        self._init_db()

    def _get_or_create_master_key(self) -> bytes:
        # Giải quyết bài toán Secret Zero: Master Key được lưu tách biệt
        if not os.path.exists(KEY_FILE):
            key = Fernet.generate_key()
            with open(KEY_FILE, "wb") as f:
                f.write(key)
            print("[Khởi tạo] Đã tạo mới Master Key an toàn.")
        with open(KEY_FILE, "rb") as f:
            return f.read()

    def _init_db(self):
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    key_name TEXT PRIMARY KEY,
                    ciphertext TEXT NOT NULL
                )
            """)
            conn.commit()

    def set_secret(self, key_name: str, secret_value: str):
        # Mã hóa bản rõ thành bản mã (Ciphertext)
        encrypted_bytes = self.cipher.encrypt(secret_value.encode("utf-8"))
        encrypted_str = encrypted_bytes.decode("utf-8")

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO secrets (key_name, ciphertext)
                VALUES (?, ?)
            """, (key_name, encrypted_str))
            conn.commit()
        print(f"[Đã lưu] Secret '{key_name}' đã được mã hóa an toàn At-Rest.")

    def get_secret(self, key_name: str) -> str:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT ciphertext FROM secrets WHERE key_name = ?", (key_name,))
            row = cursor.fetchone()
            if not row:
                raise KeyError(f"Không tìm thấy secret cho khóa: {key_name}")
            
            ciphertext = row[0].encode("utf-8")
            # Giải mã trực tiếp trong bộ nhớ RAM
            decrypted_bytes = self.cipher.decrypt(ciphertext)
            return decrypted_bytes.decode("utf-8")

if __name__ == "__main__":
    storage = SecureStorage()

    # Lưu thông tin nhạy cảm của MongoDB vào SQLite dưới dạng bản mã
    mongo_secret_uri = "mongodb://admin:SuperSecretPass2026@localhost:27017/secure_db"
    print(f"\n[1] Bản rõ ban đầu: {mongo_secret_uri}")
    
    storage.set_secret("MONGO_PRODUCTION_URI", mongo_secret_uri)

    # Đọc trực tiếp từ CSDL để minh chứng dữ liệu trên đĩa đã bị mã hóa
    with sqlite3.connect(DB_PATH) as conn:
        raw_db = conn.cursor().execute("SELECT * FROM secrets").fetchall()
        print(f"[2] Dữ liệu thực tế lưu trên đĩa (At-Rest): {raw_db}")

    # Đọc và giải mã an toàn khi cần dùng
    retrieved_secret = storage.get_secret("MONGO_PRODUCTION_URI")
    print(f"[3] Giải mã thành công trong bộ nhớ RAM: {retrieved_secret}")