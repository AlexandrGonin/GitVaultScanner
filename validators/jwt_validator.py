"""
jwt_validator.py - validate jwt tokens
"""

import base64
import json
from datetime import datetime
from typing import Any, Dict, Optional


class JwtValidator:
    """validate jwt tokens and extract claims"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

    def validate(self, token: Optional[str]) -> Dict[str, Any]:
        """
        validate jwt token structure and expiration
        returns dict with validation results
        """
        result: Dict[str, Any] = {
            "valid": False,
            "expired": False,
            "algorithm": None,
            "claims": {},
            "error": None,
        }

        if token is None:
            result["error"] = "token_required"
            return result

        try:
            # decode without verification to inspect
            parts = token.split(".")
            if len(parts) != 3:
                result["error"] = "invalid_structure"
                return result

            # decode header
            header_padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header_json = base64.urlsafe_b64decode(header_padded).decode("utf-8")
            header = json.loads(header_json)

            result["algorithm"] = header.get("alg")

            # decode payload
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(payload_padded).decode("utf-8")
            payload = json.loads(payload_json)

            # check expiration
            if "exp" in payload:
                exp = payload["exp"]
                now = datetime.now().timestamp()
                result["expired"] = exp < now
                result["expires_at"] = exp

            # check not before
            if "nbf" in payload:
                nbf = payload["nbf"]
                now = datetime.now().timestamp()
                result["not_valid_yet"] = nbf > now

            result["valid"] = True
            result["claims"] = {
                k: v for k, v in payload.items() if k not in ["exp", "nbf", "iat"]
            }

        except Exception as e:
            result["error"] = str(e)

        return result

    def get_expiry(self, token: Optional[str]) -> Optional[int]:
        """extract expiration timestamp if present"""
        if token is None:
            return None

        try:
            parts = token.split(".")
            payload_padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_json = base64.urlsafe_b64decode(payload_padded).decode("utf-8")
            payload = json.loads(payload_json)
            return payload.get("exp")
        except Exception:
            return None
