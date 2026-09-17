# storage_facade.py - Cung cấp giao diện dùng chung cho Người 5
import os
from dotenv import load_dotenv
from level2_encrypt.crypto_storage import SecureStorage

load_dotenv()

class SecretsManagerFacade:
    def __init__(self):
        self.crypto_db = SecureStorage()

    def get_env_secret(self, key_name: str) -> str:
        """Đọc secret từ biến môi trường (Mức 1)"""
        return os.getenv(key_name, "")

    def store_encrypted_secret(self, key_name: str, secret_val: str):
        """Mã hóa Fernet và lưu At-Rest (Mức 2)"""
        self.crypto_db.set_secret(key_name, secret_val)

    def retrieve_encrypted_secret(self, key_name: str) -> str:
        """Giải mã an toàn vào RAM (Mức 2)"""
        return self.crypto_db.get_secret(key_name)