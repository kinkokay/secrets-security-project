#!/usr/bin/env python3

import json
import os
import subprocess
import sys
from pathlib import Path

# Đưa thư mục gốc dự án vào sys.path để import chuẩn
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import trực tiếp hàm lõi từ scanner.py của Người 2
try:
    from scanner.scanner import scan_text, load_baseline, DEFAULT_BASELINE_PATH
except ImportError as err:
    print(f"\033[91m[LỖI IMPORT] Không thể nạp scanner.scanner:\033[0m {err}")
    sys.exit(1)

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"

ALLOWLIST_KEYWORD = "pragma: allowlist secret"
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".pdf", ".zip", ".lock", ".exe", ".bin", ".pyc"}


def get_staged_files():
    """Lấy danh sách các file đang staged (chuẩn bị commit)."""
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def get_staged_content(file_path: str) -> str:
    """Đọc nội dung staged trực tiếp từ Git Index."""
    cmd = ["git", "show", f":{file_path}"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="ignore")
    return result.stdout if result.returncode == 0 else ""


def main():
    staged_files = get_staged_files()
    if not staged_files:
        sys.exit(0)

    # Nạp danh sách secret ID đã biết từ file baseline của Người 2
    known_secret_ids = load_baseline(DEFAULT_BASELINE_PATH)
    detected_violations = []

    for file_path in staged_files:
        _, ext = os.path.splitext(file_path)
        if ext.lower() in IGNORE_EXTS or file_path.endswith(".secrets.baseline"):
            continue

        content = get_staged_content(file_path)
        if not content:
            continue

        # Gọi hàm quét mới của Người 2
        raw_findings = scan_text(content, file_path=file_path)

        for finding in raw_findings:
            line_snippet = finding["raw_snippet"]
            secret_id = finding["id"]

            # Bỏ qua nếu có comment cho phép (Inline allowlist chuẩn Yelp)
            if ALLOWLIST_KEYWORD in line_snippet:
                continue

            # Bỏ qua nếu secret ID đã nằm trong Baseline
            if secret_id in known_secret_ids:
                continue

            detected_violations.append(finding)

    # Xử lý kết quả và quyết định chặn commit
    if detected_violations:
        print(f"\n{RED}{BOLD}[NGĂN CHẶN BẢO MẬT] Đã chặn lệnh git commit!{RESET}")
        print(f"{YELLOW}Phát hiện {len(detected_violations)} secret mới chưa được duyệt trong .secrets.baseline:{RESET}\n")

        print(f"{'ID':<14} | {'Đường dẫn':<30} | {'Dòng':<5} | {'Loại':<25} | {'Masked'}")
        print("-" * 95)
        for v in detected_violations:
            print(f"{v['id']:<14} | {v['file']:<30} | {v['line']:<5} | {v['type']:<25} | {v['secret_masked']}")

        print(f"\n{BOLD}Cách khắc phục:{RESET}")
        print(f"  1. Xóa thông tin nhạy cảm khỏi code hoặc chuyển vào file {YELLOW}.env{RESET}.")
        print(f"  2. Nếu là secret an toàn/demo, thêm comment cuối dòng: {YELLOW}# pragma: allowlist secret{RESET}")
        print(f"  3. Để duyệt vào baseline, chạy: {YELLOW}py scanner/scanner.py --update-baseline{RESET}\n")
        sys.exit(1)

    print(f"{GREEN}✔ [Bảo mật] Kiểm tra hoàn tất. Không phát hiện rò rỉ secret.{RESET}")
    sys.exit(0)


if __name__ == "__main__":
    main()