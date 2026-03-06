"""
api_key_detector.py - specialized detector for api keys
"""

import re
from typing import Any, Dict, List, Optional, Tuple


class ApiKeyDetector:
    """specialized detector for various api key formats"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # service-specific key patterns
        self.service_patterns: Dict[str, List[Tuple[re.Pattern, str]]] = {
            "aws": [
                (re.compile(r"AKIA[0-9A-Z]{16}"), "aws_access_key_id"),
                (
                    re.compile(
                        r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"
                    ),
                    "aws_secret_key",
                ),
            ],
            "google": [
                (re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "google_api_key"),
                (re.compile(r"ya29\.[0-9A-Za-z\-_]+"), "google_oauth_token"),
            ],
            "github": [
                (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "github_personal_token"),
                (re.compile(r"gho_[0-9a-zA-Z]{36}"), "github_oauth_token"),
                (re.compile(r"ghu_[0-9a-zA-Z]{36}"), "github_user_token"),
                (re.compile(r"ghs_[0-9a-zA-Z]{36}"), "github_server_token"),
                (re.compile(r"ghr_[0-9a-zA-Z]{36}"), "github_refresh_token"),
            ],
            "slack": [
                (
                    re.compile(r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}"),
                    "slack_bot_token",
                ),
                (
                    re.compile(
                        r"xoxp-[0-9]{11,13}-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}"
                    ),
                    "slack_user_token",
                ),
            ],
            "stripe": [
                (re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "stripe_live_secret"),
                (re.compile(r"pk_live_[0-9a-zA-Z]{24}"), "stripe_live_public"),
                (re.compile(r"sk_test_[0-9a-zA-Z]{24}"), "stripe_test_secret"),
                (re.compile(r"pk_test_[0-9a-zA-Z]{24}"), "stripe_test_public"),
            ],
            "twilio": [
                (re.compile(r"AC[a-f0-9]{32}"), "twilio_account_sid"),
                (re.compile(r"SK[a-f0-9]{32}"), "twilio_auth_token"),
            ],
            "mailgun": [(re.compile(r"key-[0-9a-f]{32}"), "mailgun_api_key")],
            "sendgrid": [
                (
                    re.compile(r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"),
                    "sendgrid_api_key",
                )
            ],
            "discord": [
                (re.compile(r"[MN][A-Za-z\d]{23}\.[A-Za-z\d]{6}"), "discord_token")
            ],
            "telegram": [
                (re.compile(r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}"), "telegram_bot_token")
            ],
            "jwt": [
                (
                    re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
                    "jwt_token",
                )
            ],
        }

        # context keywords that increase confidence
        self.context_keywords = [
            "api_key",
            "apikey",
            "api-key",
            "secret",
            "token",
            "auth",
            "access_key",
            "accesskey",
            "client_id",
            "clientid",
            "consumer_key",
            "consumerkey",
        ]

    def detect(self, line: str, file_path: str, line_num: int) -> List[Dict[str, Any]]:
        """detect api keys in a line"""
        findings = []
        line_lower = line.lower()

        # check for context keywords
        has_context = any(kw in line_lower for kw in self.context_keywords)

        for service, patterns in self.service_patterns.items():
            for pattern, key_type in patterns:
                matches = pattern.findall(line)

                for match in matches:
                    # ensure match is a string, not a tuple
                    if isinstance(match, tuple):
                        # if it's a tuple, take the first non-empty string
                        match_str = next(
                            (str(m) for m in match if m and isinstance(m, str)), ""
                        )
                    else:
                        match_str = str(match) if match else ""

                    if (
                        not match_str
                        or len(match_str) < 10
                        or self._is_fake_key(match_str)
                    ):
                        continue

                    severity = "high"
                    if service == "jwt":
                        severity = "medium"
                    elif "test" in key_type:
                        severity = "medium"

                    # boost severity if there's context
                    if has_context and severity != "critical":
                        severity = "high"

                    findings.append(
                        {
                            "file": file_path,
                            "line": line_num,
                            "type": "api_key",
                            "service": service,
                            "key_type": key_type,
                            "value": match_str[:100]
                            if len(match_str) > 100
                            else match_str,
                            "severity": severity,
                            "has_context": has_context,
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
        ]

        key_lower = key.lower()
        return any(pattern in key_lower for pattern in fake_patterns)
