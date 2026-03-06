"""
hibp_checker.py - have i been pwned password checker
uses k-anonymity model to check passwords without sending full hash
"""

import hashlib
from typing import Dict, List, Optional

import requests


class HibpChecker:
    """check if passwords have been exposed in breaches"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.api_url = "https://api.pwnedpasswords.com/range/"
        self.timeout = self.config.get("hibp_timeout", 5)
        self.user_agent = "gitvaultscanner/1.0"

    def check_password(self, password: str) -> int:
        """
        check if password has been pwned
        returns number of times found (0 if not found)
        """
        if not password:
            return 0

        # get sha1 hash of password
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            # query api with first 5 chars of hash
            response = requests.get(
                f"{self.api_url}{prefix}",
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
            )

            if response.status_code == 200:
                # check if our hash suffix is in response
                for line in response.text.splitlines():
                    if line.startswith(suffix):
                        # format: SUFFIX:COUNT
                        count = int(line.split(":")[1])
                        return count

            return 0

        except Exception:
            # fail silently - don't block scanning if hibp is down
            return 0

    def bulk_check(self, passwords: List[str]) -> Dict[str, int]:
        """check multiple passwords"""
        results = {}
        for pwd in passwords:
            count = self.check_password(pwd)
            if count > 0:
                results[pwd] = count
        return results
