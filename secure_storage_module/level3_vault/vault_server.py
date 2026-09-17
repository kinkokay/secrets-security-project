import time
import secrets
from fastapi import FastAPI, Header, HTTPException
import uvicorn

app = FastAPI(title="Mini Secrets Vault")

# Danh sách token ứng dụng hợp lệ (Role-Based Access)
VALID_CLIENT_TOKENS = {
    "dev-app-token-123": "developer",
    "backend-prod-token-999": "production_service"
}

# Kho dữ liệu nội bộ của Vault
VAULT_DATABASE = {
    "production_service": {
        "mongo_user": "app_runner",
        "mongo_pass": "DynamicP@ssw0rd2026_Vault",
        "mongo_host": "cluster0.mongodb.net",
    }
}

@app.get("/api/v1/health")
def health_check():
    return {"status": "running", "service": "Mini-Vault"}

@app.get("/api/v1/secrets/mongo")
def get_ephemeral_mongo_credential(x_vault_token: str = Header(None)):
    # 1. Xác thực danh tính
    if not x_vault_token or x_vault_token not in VALID_CLIENT_TOKENS:
        raise HTTPException(status_code=401, detail="Xác thực thất bại: Token không hợp lệ hoặc thiếu quyền!")

    role = VALID_CLIENT_TOKENS[x_vault_token]
    if role != "production_service":
        raise HTTPException(status_code=403, detail="Từ chối truy cập: Quyền hạn không đủ để lấy tài nguyên Production!")

    # 2. Cấp phát Dynamic/Ephemeral Secret có thời hạn sống TTL (ví dụ: 60 giây)
    ttl_seconds = 60
    creds = VAULT_DATABASE["production_service"].copy()
    
    # Sinh chuỗi session ngẫu nhiên cho mỗi lượt request
    ephemeral_lease_id = f"lease_mongo_{secrets.token_hex(4)}"

    return {
        "lease_id": ephemeral_lease_id,
        "ttl": ttl_seconds,
        "expire_at": time.time() + ttl_seconds,
        "data": {
            "uri": f"mongodb://{creds['mongo_user']}:{creds['mongo_pass']}@{creds['mongo_host']}/app_db"
        }
    }

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)