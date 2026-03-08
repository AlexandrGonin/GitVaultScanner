"""
file_handler.py - file system traversal utilities
"""

import os
from typing import List, Optional


def get_files(root_dir: str, extensions: Optional[List[str]] = None) -> List[str]:
    """
    recursively get all files in directory
    filters by extensions if provided
    skips common directories to ignore
    """
    files = []

    # directories to skip
    skip_dirs = {
        ".git",
        "__pycache__",
        "node_modules",
        "venv",
        "env",
        ".venv",
        ".env",
        "dist",
        "build",
        ".idea",
        ".vscode",
        "coverage",
        "htmlcov",
        ".pytest_cache",
        ".tox",
    }

    # checking root_dir exists
    if not os.path.exists(root_dir):
        return files

    # show dir content
    try:
        os.listdir(root_dir)
    except Exception:
        return files

    # проходим по всем файлам
    for root, dirs, filenames in os.walk(root_dir):
        # modify dirs in-place to skip unwanted directories
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
        for filename in filenames:
            file_path = os.path.join(root, filename)

            # filter by extension if specified
            if extensions:
                ext = os.path.splitext(filename)[1].lower()
                if ext in extensions:
                    files.append(file_path)
            else:
                files.append(file_path)
    return files


def is_text_file(file_path: str, sample_size: int = 1024) -> bool:
    """check if file appears to be text (not binary)"""
    try:
        with open(file_path, "rb") as f:
            sample = f.read(sample_size)

        # check for null bytes - strong indicator of binary
        if b"\x00" in sample:
            return False

        # try to decode as utf-8
        sample.decode("utf-8")
        return True

    except Exception:
        return False


def read_file_lines(file_path: str) -> Optional[List[str]]:
    """read file and return lines, return none on error"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return None
