"""
source_code_parser.py - parser for source code files
"""

import os
import re
from typing import Any, Dict, List, Optional

from detectors.api_key_detector import ApiKeyDetector
from detectors.password_detector import PasswordDetector
from detectors.regex_detector import RegexDetector
from parsers.base_parser import BaseParser


class SourceCodeParser(BaseParser):
    """parser for source code files - finds hardcoded secrets in code"""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)
        self.regex_detector = RegexDetector(config)
        self.api_detector = ApiKeyDetector(config)
        self.password_detector = PasswordDetector(config)

        # patterns for variable assignments
        self.assignment_pattern = re.compile(
            r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*[\'"]([^\'"]+)[\'"]'
        )

        # keywords that indicate secret data
        self.secret_keywords = [
            "key",
            "secret",
            "token",
            "password",
            "passwd",
            "pwd",
            "api[_-]?key",
            "auth",
            "credential",
            "private",
            "access[_-]?key",
            "client[_-]?id",
            "consumer[_-]?key",
            "bearer",
            "jwt",
            "oauth",
            "app[_-]?secret",
            "encryption[_-]?key",
            "private[_-]?key",
        ]

        # compiled keyword patterns
        self.keyword_patterns = [
            re.compile(kw, re.IGNORECASE) for kw in self.secret_keywords
        ]

    def can_parse(self, file_path: str) -> bool:
        """source code parser handles most text files"""
        ext = os.path.splitext(file_path)[1].lower()

        # skip files that are better handled by other parsers
        skip_extensions = [".jpg", ".png", ".gif", ".pdf", ".zip", ".tar", ".gz"]
        skip_files = ["dockerfile", "terraform.tf", ".yml", ".yaml"]

        if ext in skip_extensions:
            return False

        filename = os.path.basename(file_path).lower()
        if any(skip in filename for skip in skip_files):
            return False

        return True

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        """parse source code file for secrets"""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        file_ext = os.path.splitext(file_path)[1].lower()

        for line_num, line in enumerate(lines, 1):
            # skip comments
            if self._is_comment(line, file_ext):
                continue

            # skip environment variable references
            if self._is_env_reference(line):
                continue

            # check for variable assignments
            findings.extend(self._check_assignments(file_path, line_num, line))

            # check for api keys using detectors
            api_findings = self.api_detector.detect(line, file_path, line_num)
            findings.extend(api_findings)

            # check for passwords
            pwd_findings = self.password_detector.detect(line, file_path, line_num)
            findings.extend(pwd_findings)

            # check generic regex patterns
            regex_findings = self.regex_detector.detect(line, file_path, line_num)
            findings.extend(regex_findings)

        return findings

    def _is_comment(self, line: str, file_ext: str) -> bool:
        """check if line is a comment"""
        stripped = line.strip()

        if file_ext == ".py":
            return stripped.startswith("#") or stripped.startswith('"""')
        elif file_ext in [".js", ".java", ".c", ".cpp", ".go", ".rs"]:
            return stripped.startswith("//") or stripped.startswith("/*")
        elif file_ext in [".html", ".xml"]:
            return stripped.startswith("<!--")
        elif file_ext in [".rb"]:
            return stripped.startswith("#")

        return False

    def _is_env_reference(self, line: str) -> bool:
        """check if line references environment variables"""
        env_patterns = [
            "os.getenv",
            "os.environ",
            "env(",
            "process.env",
            "dotenv",
            "config(",
            "environ.get",
            "getenv",
        ]
        return any(pattern in line for pattern in env_patterns)

    def _check_assignments(
        self, file_path: str, line_num: int, line: str
    ) -> List[Dict[str, Any]]:
        """check variable assignments for secrets"""
        findings = []
        match = self.assignment_pattern.search(line)

        if not match:
            return findings

        var_name, value = match.groups()

        # value too short - probably not a secret
        if len(value) < 8:
            return findings

        # check if variable name indicates secret
        is_secret_var = any(
            pattern.search(var_name) for pattern in self.keyword_patterns
        )

        # check if value looks like a secret
        looks_like_secret = self._looks_like_secret(value)

        if is_secret_var or looks_like_secret:
            severity = "high" if (is_secret_var and looks_like_secret) else "medium"

            findings.append(
                {
                    "file": file_path,
                    "line": line_num,
                    "type": "variable_assignment",
                    "variable": var_name,
                    "value": value,
                    "severity": severity,
                }
            )

        return findings

    def _looks_like_secret(self, value: str) -> bool:
        """heuristically determine if a string looks like a secret"""
        if len(value) >= 16:
            return True

        # check for mixed case with numbers
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)

        if has_upper and has_lower and has_digit:
            return True

        # check for special characters
        if re.search(r"[^a-zA-Z0-9]", value):
            return True

        return False
