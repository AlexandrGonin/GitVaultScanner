"""
regex_detector.py - regex-based pattern detection for secrets
"""

import re
from typing import Any, Dict, List, Optional

import yaml


class RegexDetector:
    """detector that uses regex patterns to find secrets"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # load patterns from config or use defaults
        self.patterns = self._load_patterns()

        # patterns to ignore (false positives)
        self.ignore_patterns = [
            re.compile(r"example\.com"),
            re.compile(r"your-key-here"),
            re.compile(r"<[^>]+>"),  # html tags
            re.compile(r"0x[0-9a-f]+", re.IGNORECASE),  # hex literals
        ]

    def _load_patterns(self) -> List[Dict[str, Any]]:
        """load regex patterns from config file"""
        default_patterns = [
            {
                "name": "aws_key",
                "pattern": r"AKIA[0-9A-Z]{16}",
                "severity": "high",
                "description": "aws access key id",
            },
            {
                "name": "aws_secret",
                "pattern": r"[0-9a-zA-Z/+]{40}",
                "severity": "high",
                "description": "aws secret access key",
            },
            {
                "name": "github_token",
                "pattern": r"gh[psu]_[0-9a-zA-Z]{36}",
                "severity": "high",
                "description": "github personal access token",
            },
            {
                "name": "github_oauth",
                "pattern": r"[0-9a-f]{40}",
                "severity": "high",
                "description": "github oauth token",
            },
            {
                "name": "slack_token",
                "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
                "severity": "high",
                "description": "slack token",
            },
            {
                "name": "private_key",
                "pattern": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
                "severity": "critical",
                "description": "private key",
            },
            {
                "name": "jwt_token",
                "pattern": r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
                "severity": "high",
                "description": "jwt token",
            },
            {
                "name": "google_api",
                "pattern": r"AIza[0-9A-Za-z\-_]{35}",
                "severity": "high",
                "description": "google api key",
            },
            {
                "name": "stripe_key",
                "pattern": r"(sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
                "severity": "high",
                "description": "stripe api key",
            },
            {
                "name": "twilio_key",
                "pattern": r"SK[0-9a-f]{32}",
                "severity": "high",
                "description": "twilio api key",
            },
            {
                "name": "ssh_private_key",
                "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
                "severity": "critical",
                "description": "ssh private key",
            },
            {
                "name": "pgp_private_key",
                "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
                "severity": "critical",
                "description": "pgp private key",
            },
            {
                "name": "generic_api_key",
                "pattern": r"[a-zA-Z0-9_\-]{20,40}",
                "severity": "medium",
                "description": "potential api key",
            },
        ]

        # try to load from yaml config
        patterns_file = self.config.get("patterns_file")
        if patterns_file and isinstance(patterns_file, str):
            try:
                with open(patterns_file, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if loaded and isinstance(loaded, dict) and "patterns" in loaded:
                        return loaded["patterns"]
            except Exception:
                pass

        return default_patterns

    def detect(self, line: str, file_path: str, line_num: int) -> List[Dict[str, Any]]:
        """detect secrets in a line using regex patterns"""
        findings = []

        for pattern_info in self.patterns:
            try:
                pattern = re.compile(pattern_info["pattern"])
                matches = pattern.findall(line)

                for match in matches:
                    # handle case where match is a tuple (from groups)
                    if isinstance(match, tuple):
                        # take the first non-empty string from the tuple
                        match_str = next(
                            (str(m) for m in match if m and isinstance(m, str)), ""
                        )
                    else:
                        match_str = str(match) if match else ""

                    if not match_str:
                        continue

                    # check if match should be ignored
                    if self._should_ignore(match_str):
                        continue

                    findings.append(
                        {
                            "file": file_path,
                            "line": line_num,
                            "type": pattern_info["name"],
                            "value": match_str[:100]
                            if len(match_str) > 100
                            else match_str,
                            "severity": pattern_info["severity"],
                            "description": pattern_info.get("description", ""),
                            "pattern_used": pattern_info["pattern"][:50],
                        }
                    )

            except re.error:
                # skip invalid patterns
                continue

        return findings

    def _should_ignore(self, value: str) -> bool:
        """check if a match should be ignored"""
        for pattern in self.ignore_patterns:
            if pattern.search(value):
                return True
        return False
