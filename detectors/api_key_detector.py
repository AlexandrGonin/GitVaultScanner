"""
api_key_detector.py - specialized detector for api keys
"""

import re
from typing import Any, Dict, List, Optional


class ApiKeyDetector:
    """detector for various api key formats"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # simple patterns
        self.patterns = [
            # AWS keys
            (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_key", "high"),
            (re.compile(r"[A-Za-z0-9/+=]{40}"), "aws_secret", "high"),
            # GitHub tokens
            (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "github_token", "high"),
            (re.compile(r"gho_[0-9a-zA-Z]{36}"), "github_token", "high"),
            (re.compile(r"ghu_[0-9a-zA-Z]{36}"), "github_token", "high"),
            (re.compile(r"ghs_[0-9a-zA-Z]{36}"), "github_token", "high"),
            (re.compile(r"ghr_[0-9a-zA-Z]{36}"), "github_token", "high"),
            # Stripe keys
            (re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "stripe_key", "high"),
            (re.compile(r"sk_test_[0-9a-zA-Z]{24,}"), "stripe_test_key", "medium"),
            # Google
            (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key", "high"),
            # Slack
            (re.compile(r"xox[baprs]-[0-9a-zA-Z]{10,48}"), "slack_token", "high"),
            # other
            (re.compile(r'["\']([A-Za-z0-9_\-]{20,40})["\']'), "generic_key", "medium"),
        ]

        # Context patterns
        self.context_patterns = [
            (
                re.compile(
                    r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE
                ),
                "api_key_context",
            ),
            (
                re.compile(r'secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
                "secret_context",
            ),
            (
                re.compile(r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']', re.IGNORECASE),
                "token_context",
            ),
            (
                re.compile(
                    r'aws[_-]?access[_-]?key[_-]?id["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    re.IGNORECASE,
                ),
                "aws_key_context",
            ),
            (
                re.compile(
                    r'github[_-]?token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    re.IGNORECASE,
                ),
                "github_token_context",
            ),
        ]

    def detect(self, line: str, file_path: str, line_num: int) -> List[Dict[str, Any]]:
        """detect api keys in a line"""
        findings = []

        # simple patterns first
        for pattern, key_type, severity in self.patterns:
            matches = pattern.findall(line)
            for match in matches:
                if isinstance(match, tuple):
                    match_str = next((str(m) for m in match if m), "")
                else:
                    match_str = str(match) if match else ""

                if (
                    match_str
                    and len(match_str) >= 8
                    and not self._is_fake_key(match_str)
                ):
                    # checking for dublicates
                    is_duplicate = False
                    for f in findings:
                        if f.get("value") == match_str:
                            is_duplicate = True
                            break

                    if not is_duplicate:
                        findings.append(
                            {
                                "file": file_path,
                                "line": line_num,
                                "type": key_type,
                                "value": match_str[:100]
                                if len(match_str) > 100
                                else match_str,
                                "severity": severity,
                                "detector": "pattern",
                            }
                        )

        # checking context patterns
        for pattern, key_type in self.context_patterns:
            matches = pattern.findall(line)
            for match in matches:
                if isinstance(match, tuple):
                    match_str = next((str(m) for m in match if m), "")
                else:
                    match_str = str(match) if match else ""

                if (
                    match_str
                    and len(match_str) >= 4
                    and not self._is_fake_key(match_str)
                ):
                    # checking for dublicates
                    is_duplicate = False
                    for f in findings:
                        if f.get("value") == match_str:
                            is_duplicate = True
                            break

                    if not is_duplicate:
                        findings.append(
                            {
                                "file": file_path,
                                "line": line_num,
                                "type": key_type,
                                "value": match_str[:100]
                                if len(match_str) > 100
                                else match_str,
                                "severity": "high" if len(match_str) > 16 else "medium",
                                "detector": "context",
                            }
                        )

        return findings

    def _is_fake_key(self, key: str) -> bool:
        """check if key is obviously fake/test"""
        fake_patterns = [
            "your-",
            "example",
            "test",
            "sample",
            "xxxx",
            "1234",
            "abcd",
            "foobar",
            "placeholder",
            "changeme",
            "your_key",
            "yourkey",
            "your-api",
            "your_secret",
            "___",
            "***",
        ]

        key_lower = key.lower()
        return any(pattern in key_lower for pattern in fake_patterns)
