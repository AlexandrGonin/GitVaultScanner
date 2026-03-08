"""
password_detector.py - detector for passwords and credentials
"""

import re
from typing import Any, Dict, List, Optional, Union


class PasswordDetector:
    """detector for passwords in various contexts"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # patterns for password finding
        self.patterns = [
            # simple assignment
            (
                re.compile(r'password\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
                "password_assign",
                "high",
            ),
            (
                re.compile(r'passwd\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
                "password_assign",
                "high",
            ),
            (
                re.compile(r'pwd\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
                "password_assign",
                "high",
            ),
            (
                re.compile(r'pass\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
                "password_assign",
                "high",
            ),
            # into json/yaml
            (
                re.compile(
                    r'["\']password["\']\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE
                ),
                "password_json",
                "high",
            ),
            (
                re.compile(
                    r'["\']passwd["\']\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE
                ),
                "password_json",
                "high",
            ),
            # db connection lines
            (re.compile(r"postgresql?://[^:]+:([^@]+)@"), "db_password", "high"),
            (re.compile(r"mysql://[^:]+:([^@]+)@"), "db_password", "high"),
            (re.compile(r"mongodb://[^:]+:([^@]+)@"), "db_password", "high"),
            (re.compile(r"redis://:([^@]+)@"), "db_password", "high"),
            (re.compile(r"rediss://:([^@]+)@"), "db_password", "high"),
        ]

        # week passwords
        self.weak_passwords = [
            "password",
            "123456",
            "qwerty",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "abc123",
            "password123",
            "passw0rd",
            "admin123",
        ]

    def detect(self, line: str, file_path: str, line_num: int) -> List[Dict[str, Any]]:
        """detect passwords in a line"""
        findings = []

        for pattern, pwd_type, severity in self.patterns:
            matches = pattern.findall(line)
            for match in matches:
                # getting str value from match
                match_str = self._extract_string(match)

                if match_str and len(match_str) >= 4:
                    # checking for dublicates
                    is_duplicate = False
                    for f in findings:
                        if f.get("value") == match_str:
                            is_duplicate = True
                            break

                    if not is_duplicate:
                        # determine the severity
                        if match_str.lower() in self.weak_passwords:
                            final_severity = "medium"
                        else:
                            final_severity = severity

                        findings.append(
                            {
                                "file": file_path,
                                "line": line_num,
                                "type": "password",
                                "subtype": pwd_type,
                                "value": match_str[:50] + "..."
                                if len(match_str) > 50
                                else match_str,
                                "severity": final_severity,
                                "length": len(match_str),
                            }
                        )

        return findings

    def _extract_string(self, match: Union[str, tuple, List, Any]) -> str:
        """getting the str from the result regex match"""
        if isinstance(match, str):
            return match
        elif isinstance(match, (tuple, list)):
            # if it's tuple or list
            for item in match:
                if item and isinstance(item, str):
                    return item
            return ""
        else:
            # if it's sth else
            return str(match) if match else ""
