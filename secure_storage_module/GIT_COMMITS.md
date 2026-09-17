# HƯỚNG DẪN CÁC LỆNH GIT COMMIT - MODULE SECURE STORAGE (NGƯỜI 3)

## 1. Cấu hình danh tính tác giả (Bắt buộc trước khi commit)
\\\ash
git config --global user.name "Your Name"
git config --global user.email "your_email@example.com"
\\\
* Ghi chú: Định danh tác giả thực hiện commit, bắt buộc phải có trên máy mới cài Git.

---

## 2. Quy trình Commit theo chuẩn Conventional Commits

### Bước 2.1: Kiểm tra an toàn trước khi thêm file (.gitignore Audit)
\\\ash
git status
\\\
* Ghi chú: Tuyệt đối không được thấy các file .env, master.key, secrets_storage.db và thư mục env/ xuất hiện trong mục Untracked files. Nếu có, phải kiểm tra lại .gitignore.

### Bước 2.2: Commit 1 - Khởi tạo mã nguồn và các module lưu trữ phân cấp
\\\ash
git add .gitignore requirements.txt .env.example level1_env/ level2_encrypt/ level3_vault/
git commit -m "feat(storage): initialize env management, fernet encryption, and mini-vault service"
\\\
* Ghi chú: 
  - level1_env/: Nạp cấu hình an toàn từ biến môi trường vào RAM.
  - level2_encrypt/: Mã hóa dữ liệu At-Rest bằng thuật toán Fernet (AES/HMAC).
  - level3_vault/: Dịch vụ két số Mini-Vault cấp Dynamic Secret có thời hạn sống (TTL).

### Bước 2.3: Commit 2 - Chuẩn hóa cấu trúc thư mục nhóm và thêm script xử lý rò rỉ
\\\ash
git add secure_storage/ storage_facade.py
git commit -m "feat(storage): standardize secure_storage package and implement remediation script"
\\\
* Ghi chú:
  - secure_storage/encrypt_fernet.py: Module mã hóa khóa chuẩn theo kiến trúc nhóm.
  - secure_storage/remediate.py: Tự động đọc scan_report.json từ Người 2 để refactor mã nguồn.
  - storage_facade.py: Lớp bao đóng (wrapper interface) bàn giao cho Người 5 tích hợp CLI/UI.

### Bước 2.4: Commit 3 - Bổ sung dữ liệu vi phạm mẫu phục vụ kiểm thử
\\\ash
git add insecure_demo.py
git commit -m "test(scanner): add hardcoded secrets demo file for hook verification"
\\\
* Ghi chú: Tệp insecure_demo.py chứa chuỗi khóa vi phạm để Người 4 kiểm tra tính năng chặn của Git Pre-commit Hook.

---

## 3. Lệnh kiểm tra lịch sử và đối soát phiên bản
\\\ash
# Xem tóm tắt các commit đã tạo
git log --oneline --graph --decorate

# Xem chi tiết các file thay đổi trong commit gần nhất
git log -1 --stat
\\\

---

## 4. Nguyên tắc an toàn thông tin áp dụng cho nhóm
1. File .env chứa secret thật trên máy local, KHÔNG BAO GIỜ được commit lên Git.
2. Khi clone/nhận code: Sao chép .env.example thành .env và điền cấu hình máy cá nhân.
3. Cài đặt thư viện đồng bộ: pip install -r requirements.txt.
