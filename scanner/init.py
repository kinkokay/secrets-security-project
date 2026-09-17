"""Module Scanner Package - Phát hiện Secrets trong mã nguồn"""

from .secret_scanner import (
    calculate_shannon_entropy,
    load_baseline,
    scan_directory,
    scan_file,
    scan_git_diff,
    scan_staged_git_files,
    scan_text,
)

__all__ = [
    "scan_file",
    "scan_directory",
    "scan_staged_git_files",
    "scan_git_diff",
    "scan_text",
    "calculate_shannon_entropy",
    "load_baseline",
]