"""
output_formatter.py - base classes for output formatting
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List


class OutputFormatter(ABC):
    """base class for all output formatters"""

    @abstractmethod
    def format_findings(
        self,
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
    ) -> str:
        """format findings into string representation"""
        pass

    @abstractmethod
    def save(
        self,
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
        output_path: str,
    ):
        """save formatted output to file"""
        pass


def severity_level(severity: str) -> int:
    """convert severity string to numeric level for sorting"""
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    return levels.get(severity.lower(), 0)


def group_by_severity(
    findings: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    """group findings by severity level"""
    grouped = {"critical": [], "high": [], "medium": [], "low": []}

    for finding in findings:
        sev = finding.get("severity", "low").lower()
        if sev in grouped:
            grouped[sev].append(finding)
        else:
            grouped["low"].append(finding)

    return grouped
