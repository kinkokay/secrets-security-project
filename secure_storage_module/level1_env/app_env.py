import os
from dotenv import load_dotenv

# Nạp các biến từ tệp .env vào os.environ trong bộ nhớ RAM
load_dotenv()

def get_mongo_connection_string():
    host = os.getenv("MONGO_HOST", "localhost")
    port = os.getenv("MONGO_PORT", "27017")
    user = os.getenv("MONGO_USER")
    password = os.getenv("MONGO_PASS")
    db_name = os.getenv("MONGO_DB_NAME", "admin")

    # Kiểm tra tính toàn vẹn của biến môi trường
    if not user or not password:
        raise ValueError("[CẢNH BÁO] Thiếu biến môi trường MONGO_USER hoặc MONGO_PASS!")

    # Ghép chuỗi kết nối an toàn lúc runtime
    connection_string = f"mongodb://{user}:{password}@{host}:{port}/{db_name}"
    
    # Masking mật khẩu khi in log để tránh lộ trong console
    masked_conn = f"mongodb://{user}:{'*' * len(password)}@{host}:{port}/{db_name}"
    print(f"[✓] Nạp cấu hình thành công: {masked_conn}")
    return connection_string

if __name__ == "__main__":
    uri = get_mongo_connection_string()
    print("[Mức 1 hoàn tất] Dữ liệu đã được nạp an toàn từ .env vào tiến trình.")