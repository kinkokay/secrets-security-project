#!/usr/bin/env python3
"""Module Scanner

Hỗ trợ:
- Quét toàn bộ / Git Staged / Git Diff.
- Sửa lỗi lọc False Positive trên các mẫu token tiêu chuẩn.
- Ghi nhận chi tiết phiên quét (Metadata: Thời gian, thư mục, chế độ).
- Quản lý trạng thái vòng đời secret tích lũy qua các phiên.
"""

from collections import Counter
from datetime import datetime
import hashlib
import json
import math
import os
import re
import subprocess
import sys

# Thiết lập đường dẫn thư mục
SCANNER_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCANNER_DIR, ".."))
DEFAULT_BASELINE_PATH = os.path.join(PROJECT_ROOT, ".secrets.baseline")
DEFAULT_REPORT_PATH = os.path.join(SCANNER_DIR, "scan_report.json")
DEFAULT_STATUS_PATH = os.path.join(SCANNER_DIR, "secrets_status.json")

# ==============================================================================
# 1. BIỂU THỨC CHÍNH QUY (REGEX RULES)
# ==============================================================================
PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub Personal Access Token": re.compile(
        r"\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"
    ),
    "JSON Web Token (JWT)": re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b"
    ),
    "Slack Bot Token": re.compile(
        r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b"
    ),
    "Private Key Header": re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    "Hardcoded Password": re.compile(
        r"""(?i)(?:password|passwd|pwd|db_pass|database_password)\s*[:=]\s*["']([^"'\s]{6,})["']"""
    ),
    "Stripe/Payment API Key": re.compile(
        r"\b(?:sk_live|rk_live|sk_test)_[0-9a-zA-Z]{24,}\b"
    ),
    "Generic API Key / Secret": re.compile(
        r"""(?i)(?:api_key|secret|access_token|auth_token|secret_key)\s*[:=]\s*["']([A-Za-z0-9_\-\.\/+=]{16,})["']"""
    ),
}

# Chỉ loại trừ khi giá trị khớp chính xác hoàn toàn với placeholder
EXACT_PLACEHOLDERS = {
    "your_api_key",
    "your_secret_here",
    "insert_key_here",
    "change_me",
    "changeme",
    "placeholder",
    "xxxxxx",
    "<token>",
    "<api_key>",
    "my_secret",
}

IGNORE_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".idea",
    ".vscode",
}
IGNORE_FILES = {
    "scan_report.json",
    "secrets_status.json",
    ".secrets.baseline",
    "secret_scanner.py",
}
IGNORE_EXTS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".pdf",
    ".zip",
    ".lock",
    ".exe",
    ".bin",
    ".pyc",
}

# ==============================================================================
# 2. THUẬT TOÁN SHANNON ENTROPY & PHÂN TÍCH NGỮ CẢNH
# ==============================================================================


def calculate_shannon_entropy(data: str) -> float:
  """Tính toán độ hỗn loạn Shannon: H(X) = -sum(P(x) * log2(P(x)))"""
  if not data:
    return 0.0
  length = len(data)
  frequencies = Counter(data)
  return round(
      -sum(
          (count / length) * math.log2(count / length)
          for count in frequencies.values()
      ),
      2,
  )


def is_high_entropy_secret(token: str) -> bool:
  if len(token) < 16:
    return False
  entropy = calculate_shannon_entropy(token)
  if re.fullmatch(r"^[0-9a-fA-F]+$", token):
    return entropy >= 3.0
  return entropy >= 4.2


def is_false_positive(secret_type: str, candidate: str, raw_line: str) -> bool:
  """Kiểm tra báo động giả an toàn không làm mất các token kiểm thử hợp lệ."""
  cand_clean = candidate.strip().lower()

  # 1. Khớp chính xác placeholder
  if cand_clean in EXACT_PLACEHOLDERS:
    return True

  # 2. Bỏ qua comment dạng ví dụ tài liệu
  line_strip = raw_line.strip()
  if (
      line_strip.startswith(("#", "//", "/*", "*", '"""', "'''"))
      and "example" in line_strip.lower()
  ):
    return True

  # 3. Chuỗi lặp đơn điệu
  if len(set(candidate)) <= 3 and len(candidate) > 10:
    return True

  return False


def mask_secret(secret: str) -> str:
  if len(secret) <= 8:
    return "***"
  return f"{secret[:3]}...{secret[-3:]}"


def generate_secret_id(file_path: str, secret_val: str) -> str:
  rel_path = os.path.relpath(file_path, PROJECT_ROOT).replace("\\", "/")
  raw_id = f"{rel_path}:{secret_val}"
  return hashlib.sha256(raw_id.encode("utf-8")).hexdigest()[:12]


# ==============================================================================
# 3. BASELINE WHITELIST (.secrets.baseline)
# ==============================================================================


def load_baseline(baseline_path: str = DEFAULT_BASELINE_PATH) -> set:
  if not os.path.exists(baseline_path):
    return set()
  try:
    with open(baseline_path, "r", encoding="utf-8") as f:
      data = json.load(f)
      return set(data.get("known_secret_ids", []))
  except Exception:
    return set()


def update_baseline_file(
    findings: list, baseline_path: str = DEFAULT_BASELINE_PATH
):
  known_ids = sorted(list({f["id"] for f in findings}))
  data = {
      "updated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
      "total_whitelisted": len(known_ids),
      "known_secret_ids": known_ids,
  }
  with open(baseline_path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
  print(
      f"[✓] Đã cập nhật {len(known_ids)} secret vào baseline:"
      f" {os.path.relpath(baseline_path, PROJECT_ROOT)}"
  )


# ==============================================================================
# 4. ENGINE QUÉT NỘI DUNG
# ==============================================================================


def scan_text(content: str, file_path: str) -> list:
  findings = []
  lines = content.splitlines()

  for line_idx, line in enumerate(lines, start=1):
    clean_line = line.strip()

    # 1. Quét biểu thức chính quy (Regex)
    for s_type, regex in PATTERNS.items():
      matches = regex.findall(clean_line)
      for match in matches:
        secret_val = match if isinstance(match, str) else match[0]
        if is_false_positive(s_type, secret_val, clean_line):
          continue

        findings.append({
            "id": generate_secret_id(file_path, secret_val),
            "file": os.path.relpath(file_path, PROJECT_ROOT).replace("\\", "/"),
            "line": line_idx,
            "type": s_type,
            "entropy": calculate_shannon_entropy(secret_val),
            "secret_masked": mask_secret(secret_val),
            "raw_secret": secret_val,
            "raw_snippet": clean_line[:100],
        })

    # 2. Quét chuỗi ngẫu nhiên cao (Chỉ chuỗi đặt trong nháy)
    quoted_tokens = re.findall(
        r"""['"]([A-Za-z0-9+/=_-]{16,})['"]""", clean_line
    )
    for token in quoted_tokens:
      if is_high_entropy_secret(token) and not is_false_positive(
          "Entropy", token, clean_line
      ):
        masked = mask_secret(token)
        if not any(
            f["line"] == line_idx and f["secret_masked"] == masked
            for f in findings
        ):
          findings.append({
              "id": generate_secret_id(file_path, token),
              "file": (
                  os.path.relpath(file_path, PROJECT_ROOT).replace("\\", "/")
              ),
              "line": line_idx,
              "type": "High Entropy String (Heuristic)",
              "entropy": calculate_shannon_entropy(token),
              "secret_masked": masked,
              "raw_secret": token,
              "raw_snippet": clean_line[:100],
          })

  return findings


def scan_file(file_path: str) -> list:
  if not os.path.isfile(file_path):
    return []
  file_name = os.path.basename(file_path)
  _, ext = os.path.splitext(file_name)

  if file_name in IGNORE_FILES or ext.lower() in IGNORE_EXTS:
    return []

  try:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
      return scan_text(f.read(), file_path)
  except Exception:
    return []


def scan_directory(target_dir: str) -> list:
  all_findings = []
  for root, dirs, files in os.walk(target_dir):
    dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
    for file in files:
      all_findings.extend(scan_file(os.path.join(root, file)))
  return all_findings


def scan_staged_git_files() -> list:
  try:
    cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
    output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(
        "utf-8"
    )
    staged_files = [
        f.strip()
        for f in output.splitlines()
        if f.strip() and os.path.isfile(f.strip())
    ]
    findings = []
    for f in staged_files:
      findings.extend(scan_file(os.path.abspath(f)))
    return findings
  except Exception:
    return []


def scan_git_diff() -> list:
  try:
    cmd = ["git", "diff", "HEAD~1", "--name-only", "--diff-filter=ACM"]
    output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode(
        "utf-8"
    )
    files = [
        f.strip()
        for f in output.splitlines()
        if f.strip() and os.path.isfile(f.strip())
    ]
    findings = []
    for f in files:
      findings.extend(scan_file(os.path.abspath(f)))
    return findings
  except Exception:
    return []


# ==============================================================================
# 5. ĐỒNG BỘ TRẠNG THÁI VÒNG ĐỜI & LỊCH SỬ PHIÊN
# ==============================================================================


def sync_status_tracking(
    current_findings: list,
    target_path: str,
    status_file: str = DEFAULT_STATUS_PATH,
):
  """Cập nhật dữ liệu tổng hợp lũy kế qua các phiên."""
  status_db = {}
  if os.path.exists(status_file):
    try:
      with open(status_file, "r", encoding="utf-8") as f:
        status_db = json.load(f)
    except Exception:
      status_db = {}

  now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  active_ids = set()

  for item in current_findings:
    s_id = item["id"]
    active_ids.add(s_id)
    if s_id not in status_db:
      status_db[s_id] = {
          "id": s_id,
          "file": item["file"],
          "line": item["line"],
          "type": item["type"],
          "entropy": item["entropy"],
          "secret_masked": item["secret_masked"],
          "status": "LEAKED (Active)",
          "first_detected": now,
          "last_seen": now,
          "scanned_source": target_path,
      }
    else:
      status_db[s_id]["status"] = "LEAKED (Active)"
      status_db[s_id]["last_seen"] = now
      status_db[s_id]["line"] = item["line"]
      status_db[s_id]["scanned_source"] = target_path

  # Đánh dấu RESOLVED cho các secret không còn tìm thấy trong mã nguồn
  for s_id, record in status_db.items():
    if s_id not in active_ids and record.get("status") == "LEAKED (Active)":
      record["status"] = "RESOLVED (Secured by Team)"
      record["resolved_at"] = now

  os.makedirs(os.path.dirname(status_file), exist_ok=True)
  with open(status_file, "w", encoding="utf-8") as f:
    json.dump(status_db, f, indent=2, ensure_ascii=False)


# ==============================================================================
# 6. GIAO DIỆN CLI VÀ XUẤT BÁO CÁO PHIÊN
# ==============================================================================


def main():
  import argparse

  parser = argparse.ArgumentParser(
      description="Secrets Scanner Module - An Toàn Bảo Mật Thông Tin"
  )
  parser.add_argument(
      "--path",
      default=None,
      help="Đường dẫn thư mục/file quét (mặc định quét toàn bộ repo)",
  )
  parser.add_argument(
      "--staged",
      action="store_true",
      help="Chế độ Git Hook: Chỉ quét các file staged",
  )
  parser.add_argument(
      "--diff",
      action="store_true",
      help="Chế độ CI/CD: Quét diff commit gần nhất",
  )
  parser.add_argument(
      "--baseline",
      default=DEFAULT_BASELINE_PATH,
      help="Đường dẫn file .secrets.baseline",
  )
  parser.add_argument(
      "--update-baseline",
      action="store_true",
      help="Ghi đè baseline bằng kết quả quét hiện tại",
  )
  args = parser.parse_args()

  # Xác định chế độ và nguồn quét
  if args.staged:
    scan_mode = "git_staged"
    scanned_path = "Git Staging Area"
    print("[*] Chế độ quét: Git Staging Area (Pre-commit Trigger)...")
    raw_findings = scan_staged_git_files()
  elif args.diff:
    scan_mode = "git_diff"
    scanned_path = "Git Diff HEAD~1"
    print("[*] Chế độ quét: Git Diff gần nhất...")
    raw_findings = scan_git_diff()
  else:
    scan_mode = "filesystem"
    target = os.path.abspath(args.path) if args.path else PROJECT_ROOT
    scanned_path = os.path.relpath(target, PROJECT_ROOT).replace("\\", "/")
    print(f"[*] Chế độ quét: Thư mục mục tiêu ({target})...")
    raw_findings = (
        scan_file(target) if os.path.isfile(target) else scan_directory(target)
    )

  if args.update_baseline:
    update_baseline_file(raw_findings, args.baseline)
    sys.exit(0)

  # Lọc baseline
  known_ids = load_baseline(args.baseline)
  new_violations = [f for f in raw_findings if f["id"] not in known_ids]

  # Cập nhật tổng hợp lũy kế
  sync_status_tracking(raw_findings, scanned_path, DEFAULT_STATUS_PATH)

  # Xuất scan_report.json có đầy đủ metadata phiên
  scan_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  report_payload = {
      "metadata": {
          "scan_time": scan_time_str,
          "scanned_directory": scanned_path,
          "scan_mode": scan_mode,
          "total_violations": len(new_violations),
          "whitelisted_in_baseline": len(raw_findings) - len(new_violations),
      },
      "violations": new_violations,
  }

  os.makedirs(SCANNER_DIR, exist_ok=True)
  with open(DEFAULT_REPORT_PATH, "w", encoding="utf-8") as f:
    json.dump(report_payload, f, indent=2, ensure_ascii=False)

  # Hiển thị bảng cảnh báo
  if new_violations:
    print(
        f"\n[!] CẢNH BÁO: PHÁT HIỆN {len(new_violations)} SECRET MỚI (CHƯA ĐƯỢC"
        " DUYỆT TRONG BASELINE)!"
    )
    print(
        f"{'ID':<14} | {'Đường dẫn':<32} | {'Dòng':<5} | {'Loại Secret':<25} |"
        f" {'Entropy':<7} | {'Giá trị Masked'}"
    )
    print("-" * 105)
    for r in new_violations:
      f_name = (
          r["file"]
          if len(r["file"]) <= 30
          else "..." + r["file"][-(30 - 3) :]
      )
      print(
          f"{r['id']:<14} | {f_name:<32} | {r['line']:<5} | {r['type']:<25} |"
          f" {r['entropy']:<7} | {r['secret_masked']}"
      )

    print(
        f"\n[+] Đã ghi đè báo cáo phiên quét:"
        f" {os.path.relpath(DEFAULT_REPORT_PATH, PROJECT_ROOT)}"
    )
    print(
        f"[+] Đã cập nhật tổng hợp vòng đời:"
        f" {os.path.relpath(DEFAULT_STATUS_PATH, PROJECT_ROOT)}"
    )
    sys.exit(1)
  else:
    print("\n[✓] MÃ NGUỒN AN TOÀN (Hoặc các secret đã nằm trong baseline).")
    print(
        f"[+] Đã ghi đè báo cáo phiên quét: scanner/scan_report.json (0"
        " vi phạm)"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()