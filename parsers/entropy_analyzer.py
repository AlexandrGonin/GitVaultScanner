"""
entropy_analyzer.py - entropy-based secret detection
uses shannon entropy to find random-looking strings
"""

import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional

from parsers.base_parser import BaseParser


class EntropyAnalyzer(BaseParser):
    """analyzer that uses entropy to detect potential secrets"""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)

        # entropy threshold - strings above this are considered random
        self.entropy_threshold = config.get("entropy_threshold", 4.2) if config else 4.2

        # minimum string length for entropy analysis
        self.min_length = config.get("min_secret_length", 8) if config else 8

        # maximum string length to analyze
        self.max_length = config.get("max_entropy_length", 200) if config else 200

        # patterns to skip (common non-secret strings)
        self.skip_patterns = [
            re.compile(r"^[0-9]+$"),  # just numbers
            re.compile(r"^[a-z]+$", re.IGNORECASE),  # just letters
            re.compile(r"^[0-9a-f]{8,}$", re.IGNORECASE),  # hex (handled separately)
            re.compile(r"^[\w\.\-]+@[\w\.\-]+\.\w+$"),  # email
            re.compile(r"^https?://"),  # url
            re.compile(r"^/[\w/]+$"),  # file path
        ]

        # patterns for hex strings (often hashes)
        self.hex_pattern = re.compile(r"^[0-9a-f]+$", re.IGNORECASE)

        # patterns for base64-like strings
        self.base64_pattern = re.compile(r"^[a-zA-Z0-9+/]+=*$")

        # patterns for jwt tokens
        self.jwt_pattern = re.compile(
            r"^[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+$"
        )

    def can_parse(self, file_path: str) -> bool:
        """entropy analyzer works on any text file"""
        return True

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        """parse file for high-entropy strings - implements BaseParser abstract method"""
        return self.analyze(file_path)

    def analyze(self, file_path: str) -> List[Dict[str, Any]]:
        """analyze file for high-entropy strings"""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        # find all potential strings in the content
        strings = self._extract_potential_strings(content)

        for line_num, string, context in strings:
            # skip if too short
            if len(string) < self.min_length:
                continue

            # skip if too long
            if len(string) > self.max_length:
                continue

            # skip common non-secret patterns
            if self._should_skip(string):
                continue

            # calculate entropy
            entropy = self._shannon_entropy(string)

            # adjust threshold for different string types
            threshold = self.entropy_threshold

            # hex strings have lower entropy naturally
            if self.hex_pattern.match(string):
                threshold = 3.0

            # base64 strings have medium entropy
            elif self.base64_pattern.match(string):
                threshold = 4.5

            # jwt tokens are high entropy
            elif self.jwt_pattern.match(string):
                threshold = 5.0

            if entropy >= threshold:
                findings.append(
                    self._create_finding(
                        file_path,
                        line_num,
                        "high_entropy_string",
                        string,
                        severity="medium",
                        entropy=round(entropy, 2),
                        context=context[:100] if context else "",
                    )
                )

        return findings

    def _extract_potential_strings(self, content: str) -> List[tuple]:
        """extract potential secret strings from content"""
        strings = []
        lines = content.split("\n")

        for line_num, line in enumerate(lines, 1):
            # find quoted strings
            quoted = re.findall(r'[\'"]([^\'"]{8,})[\'"]', line)
            for s in quoted:
                strings.append((line_num, s, line.strip()))

            # find potential tokens (no quotes, but surrounded by non-word chars)
            tokens = re.findall(r"\b([a-zA-Z0-9+/=_-]{12,})\b", line)
            for token in tokens:
                # avoid duplicates with quoted strings
                if token not in quoted:
                    strings.append((line_num, token, line.strip()))

        return strings

    def _shannon_entropy(self, data: str) -> float:
        """calculate shannon entropy of a string"""
        if not data:
            return 0.0

        entropy = 0.0
        length = len(data)

        # count character frequencies
        freq = Counter(data)

        # calculate entropy
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def _should_skip(self, string: str) -> bool:
        """check if string should be skipped (not a secret)"""
        # skip if matches any skip pattern
        for pattern in self.skip_patterns:
            if pattern.match(string):
                return True

        # skip if it's a common word
        common_words = {
            "password",
            "username",
            "localhost",
            "database",
            "connection",
            "default",
            "example",
            "test123",
        }
        if string.lower() in common_words:
            return True

        # skip if it's a version number
        if re.match(r"^\d+\.\d+\.\d+$", string):
            return True

        return False
