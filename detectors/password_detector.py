"""
password_detector.py - detector for passwords and credentials
"""

import re
from typing import Any, Dict, List, Optional


class PasswordDetector:
    """detector for passwords in various contexts"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # password patterns in assignments
        self.password_assignments = [
            (
                re.compile(r'password\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
                "password_eq",
            ),
            (
                re.compile(r'passwd\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
                "passwd_eq",
            ),
            (re.compile(r'pwd\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE), "pwd_eq"),
            (re.compile(r'pass\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE), "pass_eq"),
        ]

        # password patterns in dictionaries
        self.password_dict = [
            (
                re.compile(
                    r'[\'"]password[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE
                ),
                "dict_password",
            ),
            (
                re.compile(
                    r'[\'"]passwd[\'"]\s*:\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE
                ),
                "dict_passwd",
            ),
        ]

        # connection string patterns
        self.connection_strings = [
            (re.compile(r"postgres(?:ql)?://[^:]+:([^@]+)@"), "postgres_pwd"),
            (re.compile(r"mysql://[^:]+:([^@]+)@"), "mysql_pwd"),
            (re.compile(r"mongodb(?:\+srv)?://[^:]+:([^@]+)@"), "mongodb_pwd"),
            (re.compile(r"redis://[^:]+:([^@]+)@"), "redis_pwd"),
            (re.compile(r"rediss://[^:]+:([^@]+)@"), "rediss_pwd"),
        ]

        # function parameter patterns
        self.function_params = [
            (
                re.compile(
                    r'connect\([^)]*password=([\'"][^\'"]+[\'"])', re.IGNORECASE
                ),
                "connect_pwd",
            ),
            (
                re.compile(r'login\([^)]*password=([\'"][^\'"]+[\'"])', re.IGNORECASE),
                "login_pwd",
            ),
            (
                re.compile(
                    r'authenticate\([^)]*password=([\'"][^\'"]+[\'"])', re.IGNORECASE
                ),
                "auth_pwd",
            ),
        ]

        # weak password patterns (to flag)
        self.weak_passwords = [
            re.compile(r"^password$", re.IGNORECASE),
            re.compile(r"^123456"),
            re.compile(r"^qwerty"),
            re.compile(r"^admin"),
            re.compile(r"^letmein"),
            re.compile(r"^welcome"),
            re.compile(r"^monkey"),
            re.compile(r"^abc123"),
        ]

    def detect(self, line: str, file_path: str, line_num: int) -> List[Dict[str, Any]]:
        """detect passwords in a line"""
        findings = []

        # check password assignments
        for pattern, finding_type in self.password_assignments:
            matches = pattern.findall(line)
            for match in matches:
                if self._is_actual_password(match):
                    findings.append(
                        self._create_finding(file_path, line_num, finding_type, match)
                    )

        # check dictionary patterns
        for pattern, finding_type in self.password_dict:
            matches = pattern.findall(line)
            for match in matches:
                if self._is_actual_password(match):
                    findings.append(
                        self._create_finding(file_path, line_num, finding_type, match)
                    )

        # check connection strings
        for pattern, finding_type in self.connection_strings:
            match = pattern.search(line)
            if match:
                password = match.group(1)
                if password and len(password) >= 4:
                    findings.append(
                        self._create_finding(
                            file_path,
                            line_num,
                            finding_type,
                            password,
                            connection_string=match.group(0)[:100],
                        )
                    )

        # check function parameters
        for pattern, finding_type in self.function_params:
            matches = pattern.findall(line)
            for match in matches:
                # strip quotes
                password = match.strip("'\"")
                if self._is_actual_password(password):
                    findings.append(
                        self._create_finding(
                            file_path, line_num, finding_type, password
                        )
                    )

        return findings

    def _is_actual_password(self, password: str) -> bool:
        """determine if string is likely an actual password"""
        # too short
        if len(password) < 4:
            return False

        # placeholder values
        placeholders = ["your_password", "password123", "changeme", "secret"]
        if password.lower() in placeholders:
            return False

        # check if it's a weak password (still a password, just weak)
        is_weak = any(p.match(password) for p in self.weak_passwords)

        # it's a password if it has mixed characteristics
        has_letter = any(c.isalpha() for c in password)
        has_digit = any(c.isdigit() for c in password)

        return has_letter or has_digit or is_weak

    def _create_finding(
        self, file_path: str, line_num: int, finding_type: str, password: str, **kwargs
    ) -> Dict[str, Any]:
        """create a password finding"""
        severity = "high"

        # check if weak password
        if any(p.match(password) for p in self.weak_passwords):
            severity = "medium"

        # check if placeholder
        if password.lower() in ["password", "secret", "changeme"]:
            severity = "low"

        finding = {
            "file": file_path,
            "line": line_num,
            "type": "password",
            "subtype": finding_type,
            "value": password[:50] + "..." if len(password) > 50 else password,
            "severity": severity,
            "length": len(password),
        }

        finding.update(kwargs)
        return finding
