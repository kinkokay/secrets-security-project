#!/usr/bin/env python3
import os
import stat
import sys
from pathlib import Path

def install_hook():
    git_dir = Path(".git")
    if not git_dir.is_dir():
        print("[LỖI] Không tìm thấy thư mục .git! Hãy gõ 'git init' trước.")
        sys.exit(1)

    hook_path = git_dir / "hooks" / "pre-commit"
    hook_script = """#!/bin/sh
python3 hooks/pre_commit.py
"""
    with open(hook_path, "w", encoding="utf-8") as f:
        f.write(hook_script)

    current_stat = os.stat(hook_path)
    os.chmod(hook_path, current_stat.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    print("[THÀNH CÔNG] Đã kích hoạt Pre-commit Hook tự động.")

if __name__ == "__main__":
    install_hook()