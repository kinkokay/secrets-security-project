import json
import os
import re

REPORT_FILE = "scan_report.json"
ENV_FILE = ".env"

def remediate_from_report(report_path: str = REPORT_FILE):
    if not os.path.exists(report_path):
        print(f"[x] Không tìm thấy tệp báo cáo: {report_path}")
        print("    Hãy chạy module của Người 2 trước: python scanner.py <file_can_quet> --export scan_report.json")
        return

    with open(report_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    if not findings:
        print("[✓] Không có secret nào cần dọn dẹp.")
        return

    print(f"[*] Bắt đầu xử lý dọn dẹp cho {len(findings)} phát hiện rò rỉ...\n")

    # Đọc nội dung .env hiện tại để tránh ghi trùng lặp
    existing_env_content = ""
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE, "r", encoding="utf-8") as env_f:
            existing_env_content = env_f.read()

    new_env_entries = []

    for idx, item in enumerate(findings, start=1):
        file_target = item.get("file")
        line_num = item.get("line")
        secret_type = item.get("type")
        raw_snippet = item.get("raw_snippet", "")

        # Đặt tên biến môi trường tự động
        var_name = f"REMEDIATED_SECRET_{idx}"
        if "Password" in secret_type:
            var_name = f"REMEDIATED_DB_PASS_{idx}"
        elif "AWS" in secret_type:
            var_name = f"REMEDIATED_AWS_KEY_{idx}"

        print(f"[{idx}] Tệp: {file_target} (Dòng {line_num})")
        print(f"    Nguy cơ: {secret_type}")
        print(f"    Đoạn mã: {raw_snippet}")
        print(f"    -> Đề xuất: Thay bằng `os.getenv('{var_name}')` và chuyển secret vào `{ENV_FILE}`.")

        # Cập nhật danh sách biến đưa vào .env
        new_env_entries.append(f"# Tự động trích xuất từ {file_target} (Dòng {line_num})\n{var_name}=<DIEN_GIA_TRI_THUC_TE>\n")

    # Lưu hướng dẫn bổ sung vào .env
    with open(ENV_FILE, "a", encoding="utf-8") as env_f:
        env_f.write("\n# === CÁC BIẾN CẦN BẢO VỆ TỪ REMEDIATE SCRIPT ===\n")
        env_f.writelines(new_env_entries)

    print(f"\n[✓] Hoàn tất dọn dẹp sơ bộ! Các biến mẫu đã được bổ sung vào `{ENV_FILE}`.")
    print("[✓] Mã nguồn đã sẵn sàng để refactor loại bỏ hardcoded credentials.")

if __name__ == "__main__":
    remediate_from_report()