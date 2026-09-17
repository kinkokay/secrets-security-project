import requests
import time

VAULT_URL = "http://127.0.0.1:8000/api/v1/secrets/mongo"

def fetch_secret_from_vault(token: str):
    headers = {"X-Vault-Token": token}
    response = requests.get(VAULT_URL, headers=headers)
    
    if response.status_code == 200:
        res_data = response.json()
        print(f"\n[✓] Lấy secret thành công từ Vault!")
        print(f"    Lease ID: {res_data['lease_id']}")
        print(f"    Thời gian sống (TTL): {res_data['ttl']} giây")
        print(f"    Chuỗi MongoDB cấp phát: {res_data['data']['uri']}")
    else:
        print(f"\n[x] Lỗi ({response.status_code}): {response.json().get('detail')}")

if __name__ == "__main__":
    print("--- Thử nghiệm 1: Gửi Token sai ---")
    fetch_secret_from_vault("fake-invalid-token")

    print("\n--- Thử nghiệm 2: Gửi Token quyền thấp (Developer) ---")
    fetch_secret_from_vault("dev-app-token-123")

    print("\n--- Thử nghiệm 3: Gửi Token hợp lệ của Production Service ---")
    fetch_secret_from_vault("backend-prod-token-999")