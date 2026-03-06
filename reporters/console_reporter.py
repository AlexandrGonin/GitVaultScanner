"""
console_reporter.py - console output formatting
"""

import os
from datetime import datetime
from typing import Any, Dict, List


class ConsoleReporter:
    """reporter for console output"""

    @staticmethod
    def print_report(
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
    ):
        """print findings to console"""
        print("\n" + "=" * 80)
        print(f"SCAN RESULTS - {target_name}")
        print("=" * 80)

        if not findings:
            print("\nno secrets found")
            print(f"\nscan completed in {scan_time:.2f} seconds")
            return

        # count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["low"] += 1

        print("\nsummary:")
        print(f"  total findings: {len(findings)}")
        print(f"  critical: {severity_counts['critical']}")
        print(f"  high: {severity_counts['high']}")
        print(f"  medium: {severity_counts['medium']}")
        print(f"  low: {severity_counts['low']}")

        print("\ndetailed findings:")
        print("-" * 80)

        # group by severity for display
        for severity in ["critical", "high", "medium", "low"]:
            sev_findings = [
                f for f in findings if f.get("severity", "low").lower() == severity
            ]

            if sev_findings:
                print(f"\n[{severity.upper()}]")
                for idx, finding in enumerate(sev_findings, 1):
                    file_path = finding.get("file", "unknown")
                    line = finding.get("line", 0)
                    finding_type = finding.get("type", "unknown")
                    value = finding.get("value", "")

                    print(f"  {idx}. {os.path.basename(file_path)}:{line}")
                    print(f"     type: {finding_type}")
                    if finding.get("variable"):
                        print(f"     variable: {finding['variable']}")
                    print(f"     value: {value[:80]}")

                    if finding.get("valid") is not None:
                        print(f"     valid: {finding['valid']}")
                    if finding.get("expired") is not None:
                        print(f"     expired: {finding['expired']}")
                    if finding.get("pwned"):
                        print(
                            f"     pwned: yes ({finding.get('pwned_count', 0)} times)"
                        )

        print(f"\nscan completed in {scan_time:.2f} seconds")

    @staticmethod
    def save_text_report(
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
        output_path: str,
    ):
        """save findings as text file"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("GITVAULTSCANNER REPORT\n")
            f.write("=" * 80 + "\n\n")

            f.write(f"target: {target_name}\n")
            f.write(f"scan type: {scan_type}\n")
            f.write(f"scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"scan duration: {scan_time:.2f} seconds\n")
            f.write(f"total findings: {len(findings)}\n\n")

            if not findings:
                f.write("no secrets found\n")
                return

            for idx, finding in enumerate(findings, 1):
                f.write(f"[{idx}] {finding.get('severity', 'unknown').upper()}\n")
                f.write(f"    file: {finding.get('file', 'unknown')}\n")
                f.write(f"    line: {finding.get('line', 0)}\n")
                f.write(f"    type: {finding.get('type', 'unknown')}\n")
                if finding.get("variable"):
                    f.write(f"    variable: {finding['variable']}\n")
                f.write(f"    value: {finding.get('value', '')}\n")

                # additional fields
                for key in ["service", "algorithm", "valid", "expired", "pwned"]:
                    if key in finding:
                        f.write(f"    {key}: {finding[key]}\n")

                f.write("-" * 60 + "\n")
