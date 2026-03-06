"""
jwt_detector.py - detector for jwt tokens
"""

import base64
import json
import re
from typing import Any, Dict, List, Optional


class JwtDetector:
    """detector for jwt tokens with basic validation"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # jwt pattern
        self.jwt_pattern = re.compile(
            r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
        )

        # patterns for jwt in different contexts
        self.context_patterns = [
            re.compile(r"authorization:\s*bearer\s+([^\s]+)", re.IGNORECASE),
            re.compile(r"x-access-token:\s*([^\s]+)", re.IGNORECASE),
            re.compile(r'token":\s*"([^"]+)"'),
            re.compile(r'jwt":\s*"([^"]+)"'),
        ]

    def detect(self, line: str, file_path: str, line_num: int) -> List[Dict[str, Any]]:
        """detect jwt tokens in a line"""
        findings = []

        # find all potential jwt tokens
        matches = self.jwt_pattern.findall(line)

        # check context patterns
        for pattern in self.context_patterns:
            context_matches = pattern.findall(line)
            matches.extend(context_matches)

        for token in matches:
            # validate token structure
            validation = self._validate_jwt(token)

            if validation.get("valid", False):
                finding: Dict[str, Any] = {
                    "file": file_path,
                    "line": line_num,
                    "type": "jwt_token",
                    "value": token[:50] + "..." if len(token) > 50 else token,
                    "severity": "high",
                    "algorithm": validation.get("algorithm", "unknown"),
                    "has_expiry": validation.get("has_expiry", False),
                }

                # add claims if we could decode them
                if validation.get("claims"):
                    finding["claims"] = validation["claims"]

                findings.append(finding)

        return findings

    def _validate_jwt(self, token: str) -> Dict[str, Any]:
        """validate jwt token structure and decode header"""
        result: Dict[str, Any] = {"valid": False}

        parts = token.split(".")
        if len(parts) != 3:
            return result

        try:
            # decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_padded).decode("utf-8")
            header = json.loads(header_json)

            result["algorithm"] = header.get("alg", "unknown")
            result["type"] = header.get("typ", "JWT")

            # decode payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(payload_padded).decode("utf-8")
            payload = json.loads(payload_json)

            # check for expiry
            if "exp" in payload:
                result["has_expiry"] = True
                result["expiry"] = payload["exp"]

            # store claims (without sensitive data)
            safe_claims = {
                k: v
                for k, v in payload.items()
                if k not in ["password", "secret", "token"]
            }
            result["claims"] = safe_claims

            result["valid"] = True

        except Exception:
            # not a valid jwt
            pass

        return result
