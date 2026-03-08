"""
hibp_checker.py - have i been pwned password checker
uses k-anonymity model to check passwords without sending full hash
"""

import hashlib
from datetime import datetime
from functools import lru_cache
from typing import Any, Dict, List, Optional

import requests


class HibpChecker:
    """check if passwords have been exposed in breaches"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}

        # multiple API endpoints for fallback
        self.api_urls = [
            "https://api.pwnedpasswords.com/range/",
            "https://pwnedpasswords.com/range/",
        ]
        self.timeout = self.config.get("hibp_timeout", 5)
        self.user_agent = self.config.get("hibp_user_agent", "gitvaultscanner/1.0")

        # statistics for reporting
        self.stats = {
            "total_checked": 0,
            "total_pwned": 0,
            "pwned_passwords": [],
            "errors": 0,
            "response_time": 0,
        }

    @lru_cache(maxsize=1000)
    def check_password(self, password: Optional[str]) -> int:
        """
        check if password has been pwned
        returns number of times found (0 if not found)
        uses caching to avoid repeated API calls
        """
        import time

        start_time = time.time()

        self.stats["total_checked"] += 1

        if password is None or not password:
            return 0

        # get sha1 hash of password
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        # try each API endpoint until one works
        for api_url in self.api_urls:
            try:
                url = f"{api_url}{prefix}"

                response = requests.get(
                    url, headers={"User-Agent": self.user_agent}, timeout=self.timeout
                )

                if response.status_code == 200:
                    # check if our hash suffix is in response
                    for line in response.text.splitlines():
                        if line.startswith(suffix):
                            count = int(line.split(":")[1])

                            # update statistics
                            self.stats["total_pwned"] += 1
                            self.stats["pwned_passwords"].append(
                                {
                                    "password": password[:20] + "..."
                                    if len(password) > 20
                                    else password,
                                    "hash": sha1_hash,
                                    "count": count,
                                    "timestamp": datetime.now().isoformat(),
                                }
                            )
                            self.stats["response_time"] = time.time() - start_time

                            return count

                    # password not found
                    self.stats["response_time"] = time.time() - start_time
                    return 0

            except requests.exceptions.Timeout:
                self.stats["errors"] += 1
                continue
            except requests.exceptions.ConnectionError:
                self.stats["errors"] += 1
                continue
            except Exception:
                self.stats["errors"] += 1
                continue

        # all APIs failed
        self.stats["errors"] += 1
        return 0

    def bulk_check(self, passwords: List[str]) -> Dict[str, int]:
        """check multiple passwords"""
        results = {}
        for pwd in passwords:
            if pwd:
                count = self.check_password(pwd)
                if count > 0:
                    results[pwd] = count
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """return statistics about HIBP checks"""
        return {
            "total_passwords_checked": self.stats["total_checked"],
            "total_pwned_found": self.stats["total_pwned"],
            "pwned_passwords": self.stats["pwned_passwords"][
                -10:
            ],  # last 10 for report
            "api_errors": self.stats["errors"],
            "average_response_time": round(self.stats["response_time"], 3)
            if self.stats["response_time"]
            else 0,
        }

    def reset_statistics(self):
        """reset statistics (useful for new scans)"""
        self.stats = {
            "total_checked": 0,
            "total_pwned": 0,
            "pwned_passwords": [],
            "errors": 0,
            "response_time": 0,
        }
