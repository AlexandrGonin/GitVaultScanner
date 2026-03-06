"""
binary_parser.py - parser for binary files
extracts strings and searches for secrets
"""

import re
import subprocess
from typing import Any, Dict, List, Optional

from parsers.base_parser import BaseParser


class BinaryParser(BaseParser):
    """parser for binary files - extracts strings and searches for secrets"""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)

        # minimum string length to consider
        self.min_string_length = 8
        if config is not None:
            self.min_string_length = config.get("binary_min_string_length", 8)

        # patterns for secrets in binary files
        self.secret_patterns = [
            (re.compile(r"[a-f0-9]{32,40}", re.IGNORECASE), "md5_sha_hash"),
            (re.compile(r"[A-Z0-9]{20,40}"), "api_key_uppercase"),
            (re.compile(r"https?://[^\s]+"), "url"),
            (re.compile(r"postgresql://[^\s]+"), "db_url"),
            (re.compile(r"mysql://[^\s]+"), "mysql_url"),
            (re.compile(r"mongodb://[^\s]+"), "mongodb_url"),
            (re.compile(r"redis://[^\s]+"), "redis_url"),
            (re.compile(r"-----BEGIN [A-Z ]+-----"), "private_key"),
        ]

        # try to use system strings command
        self.has_strings_cmd = self._check_strings_command()

    def can_parse(self, file_path: str) -> bool:
        """check if file is binary"""
        try:
            with open(file_path, "rb") as f:
                sample = f.read(1024)
            return b"\x00" in sample  # null bytes indicate binary
        except Exception:
            return False

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        """extract strings from binary and search for secrets"""
        findings = []

        # extract strings from binary
        strings = self._extract_strings(file_path)

        for line_num, string in enumerate(strings, 1):
            # skip short strings
            if len(string) < self.min_string_length:
                continue

            # check each pattern
            for pattern, finding_type in self.secret_patterns:
                matches = pattern.findall(string)
                for match in matches:
                    findings.append(
                        self._create_finding(
                            file_path,
                            line_num,
                            finding_type,
                            match,
                            severity="high" if len(match) > 20 else "medium",
                            context=string[:100],
                        )
                    )

        return findings

    def _extract_strings(self, file_path: str) -> List[str]:
        """extract printable strings from binary file"""
        strings = []

        # try using system strings command first
        if self.has_strings_cmd:
            try:
                result = subprocess.run(
                    ["strings", file_path], capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0:
                    return [s.strip() for s in result.stdout.split("\n") if s.strip()]
            except Exception:
                pass

        # fallback to manual extraction
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            current = []
            for byte in data:
                if 32 <= byte <= 126:  # printable ascii
                    current.append(chr(byte))
                else:
                    if len(current) >= self.min_string_length:
                        strings.append("".join(current))
                    current = []

            # add last string if any
            if len(current) >= self.min_string_length:
                strings.append("".join(current))

        except Exception:
            pass

        return strings

    def _check_strings_command(self) -> bool:
        """check if system strings command is available"""
        try:
            result = subprocess.run(
                ["strings", "--version"], capture_output=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
