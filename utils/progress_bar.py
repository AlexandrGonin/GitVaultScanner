"""
progress_bar.py - simple progress bar for terminal
"""

import sys


class ProgressBar:
    """simple progress bar for terminal output"""

    def __init__(self, total: int, width: int = 50):
        self.total = total
        self.width = width
        self.current = 0

    def update(self, current: int, message: str = ""):
        """update progress bar position"""
        self.current = current
        percent = current / self.total
        filled = int(self.width * percent)
        bar = "█" * filled + "░" * (self.width - filled)

        sys.stdout.write(f"\r[{bar}] {current}/{self.total} {message}")
        sys.stdout.flush()

    def finish(self):
        """complete the progress bar"""
        self.update(self.total, "done")
        sys.stdout.write("\n")
