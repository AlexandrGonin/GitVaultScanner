"""
json_reporter.py - json output formatting
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional


class JsonReporter:
    """reporter for json output"""

    @staticmethod
    def save_report(
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
        output_path: str,
        hibp_stats: Optional[Dict] = None,
    ):
        """save findings as json file"""

        report = {
            "metadata": {
                "tool": "gitvaultscanner",
                "version": "1.0.0",
                "target": target_name,
                "scan_type": scan_type,
                "scan_date": datetime.now().isoformat(),
                "scan_duration": scan_time,
                "total_findings": len(findings),
            },
            "summary": {
                "by_severity": JsonReporter._count_by_severity(findings),
                "by_type": JsonReporter._count_by_type(findings),
            },
            "findings": findings,
        }

        # add HIBP statistics if available
        if hibp_stats and hibp_stats.get("total_pwned_found", 0) > 0:
            report["hibp_statistics"] = hibp_stats

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """count findings by severity"""
        counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _count_by_type(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """count findings by type"""
        counts = {}
        for f in findings:
            ftype = f.get("type", "unknown")
            counts[ftype] = counts.get(ftype, 0) + 1
        return counts
