"""
docker_parser.py - parser for dockerfiles and container configurations
"""

import os
import re
from typing import Any, Dict, List, Optional

from parsers.base_parser import BaseParser


class DockerParser(BaseParser):
    """parser for dockerfiles - finds secrets in docker instructions"""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)

        # patterns for dangerous docker instructions
        self.dangerous_patterns = [
            (
                re.compile(r'ENV\s+(\w+)\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
                "env_variable",
            ),
            (
                re.compile(r'ARG\s+(\w+)\s*=\s*[\'"]([^\'"]+)[\'"]', re.IGNORECASE),
                "build_arg",
            ),
            (
                re.compile(r"ADD\s+--chown=.*?\s+(\S+)\s+", re.IGNORECASE),
                "add_with_credentials",
            ),
            (
                re.compile(r"COPY\s+--chown=.*?\s+(\S+)\s+", re.IGNORECASE),
                "copy_with_credentials",
            ),
        ]

        # patterns for secrets in run commands
        self.run_secret_patterns = [
            (
                re.compile(r"curl\s+.*?-u\s+([^:\s]+:[^\s]+)", re.IGNORECASE),
                "curl_with_auth",
            ),
            (
                re.compile(r"wget\s+.*?--user\s*=\s*([^\s]+)", re.IGNORECASE),
                "wget_with_auth",
            ),
            (
                re.compile(r"git\s+clone\s+https?://[^@]+@", re.IGNORECASE),
                "git_with_credentials",
            ),
            (
                re.compile(r"pip\s+install\s+.*?--extra-index-url.*?\s", re.IGNORECASE),
                "pip_private_repo",
            ),
        ]

        # patterns for secrets in environment variables
        self.env_secret_patterns = [
            re.compile(r"password|passwd|pwd|token|secret|key", re.IGNORECASE)
        ]

    def can_parse(self, file_path: str) -> bool:
        """check if file is a dockerfile"""
        filename = os.path.basename(file_path).lower()
        return (
            filename == "dockerfile"
            or filename.endswith(".dockerfile")
            or filename == "containerfile"
        )

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        """parse dockerfile for secrets"""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # skip comments
            if stripped.startswith("#"):
                continue

            # check dangerous instructions
            for pattern, finding_type in self.dangerous_patterns:
                match = pattern.search(line)
                if match:
                    value = (
                        match.group(2) if len(match.groups()) > 1 else match.group(1)
                    )

                    # check if value looks like a secret
                    if self._is_potential_secret(value):
                        findings.append(
                            self._create_finding(
                                file_path,
                                line_num,
                                finding_type,
                                value,
                                severity="high"
                                if self._is_high_risk(value)
                                else "medium",
                                instruction=match.group(0),
                            )
                        )

            # check run commands
            if stripped.startswith("RUN"):
                for pattern, finding_type in self.run_secret_patterns:
                    match = pattern.search(line)
                    if match:
                        value = match.group(1) if match.groups() else match.group(0)
                        findings.append(
                            self._create_finding(
                                file_path,
                                line_num,
                                finding_type,
                                value,
                                severity="high",
                                command=line[:100],
                            )
                        )

        return findings

    def _is_potential_secret(self, value: str) -> bool:
        """check if a value might be a secret"""
        if len(value) < 8:
            return False

        # check for common secret patterns
        for pattern in self.env_secret_patterns:
            if pattern.search(value):
                return True

        # check entropy-like characteristics
        if re.search(r"[A-Z]{5,}", value) or re.search(r"[0-9]{8,}", value):
            return True

        return False

    def _is_high_risk(self, value: str) -> bool:
        """determine if secret is high risk"""
        high_risk_patterns = [
            r"password|passwd|pwd|token|secret",  # explicit secret names
            r"[A-Z0-9]{20,}",  # long random strings
            r"[\w\-]{36,}",  # uuid-like
            r"sk_[a-zA-Z0-9]{24,}",  # secret keys starting with sk_
        ]

        return any(re.search(p, value, re.IGNORECASE) for p in high_risk_patterns)
