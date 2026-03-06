"""
base_parser.py - abstract base class for all parsers
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseParser(ABC):
    """abstract base class for all file parsers"""

    def __init__(self, config: Optional[Dict] = None):
        """initialize parser with configuration"""
        self.config = config or {}

    @abstractmethod
    def can_parse(self, file_path: str) -> bool:
        """return true if this parser can handle the file"""
        pass

    @abstractmethod
    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        """parse file and return list of findings"""
        pass

    def _create_finding(
        self,
        file_path: str,
        line_number: int,
        finding_type: str,
        value: str,
        severity: str = "medium",
        **kwargs,
    ) -> Dict[str, Any]:
        """create a standardized finding dictionary"""
        finding = {
            "file": file_path,
            "line": line_number,
            "type": finding_type,
            "value": value[:200] if len(value) > 200 else value,
            "severity": severity,
            "timestamp": kwargs.get("timestamp"),
            "context": kwargs.get("context", ""),
            "validator": kwargs.get("validator"),
        }

        # add any extra fields
        for key, val in kwargs.items():
            if key not in finding:
                finding[key] = val

        return finding
