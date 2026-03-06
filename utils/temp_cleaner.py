"""
temp_cleaner.py - temporary file cleanup utilities
"""

import os
import shutil
import tempfile
import time
from typing import Optional


def cleanup_temp_dirs(temp_dir: str, max_age_hours: int = 24):
    """
    remove temporary directory
    optionally clean up old temp dirs
    """
    try:
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
    except Exception as e:
        # log but don't fail
        print(f"warning: could not clean up {temp_dir}: {e}")


def cleanup_old_temp_dirs(temp_base: Optional[str] = None, max_age_hours: int = 24):
    """
    remove temporary directories older than max_age_hours
    """
    if temp_base is None:
        temp_base = tempfile.gettempdir()

    now = time.time()
    max_age_seconds = max_age_hours * 3600

    try:
        for item in os.listdir(temp_base):
            if item.startswith("gvs_"):
                item_path = os.path.join(temp_base, item)
                if os.path.isdir(item_path):
                    age = now - os.path.getctime(item_path)
                    if age > max_age_seconds:
                        shutil.rmtree(item_path, ignore_errors=True)
    except Exception:
        pass


def register_cleanup_hook(temp_dir: str):
    """register a function to clean up on exit"""
    import atexit

    atexit.register(cleanup_temp_dirs, temp_dir)
