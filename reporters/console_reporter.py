"""
console_reporter.py - console output formatting
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

# ANSI colors for output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"


class ConsoleReporter:
    """reporter for console output"""

    @staticmethod
    def print_report(
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
        hibp_stats: Optional[Dict] = None,
    ):
        """print findings to console"""
        print(f"\n{BLUE}{'=' * 80}{RESET}")
        print(f"{BLUE}SCAN RESULTS - {target_name}{RESET}")
        print(f"{BLUE}{'=' * 80}{RESET}")

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
        print(
            f"  {RED if severity_counts['critical'] > 0 else ''}critical: {severity_counts['critical']}{RESET}"
        )
        print(
            f"  {RED if severity_counts['high'] > 0 else ''}high: {severity_counts['high']}{RESET}"
        )
        print(
            f"  {YELLOW if severity_counts['medium'] > 0 else ''}medium: {severity_counts['medium']}{RESET}"
        )
        print(
            f"  {GREEN if severity_counts['low'] > 0 else ''}low: {severity_counts['low']}{RESET}"
        )

        print("\ndetailed findings:")
        print(f"{BLUE}{'-' * 80}{RESET}")

        # group by severity for display
        for severity in ["critical", "high", "medium", "low"]:
            sev_findings = [
                f for f in findings if f.get("severity", "low").lower() == severity
            ]

            if sev_findings:
                if severity == "critical":
                    color = RED
                elif severity == "high":
                    color = RED
                elif severity == "medium":
                    color = YELLOW
                else:
                    color = GREEN

                print(f"\n{color}[{severity.upper()}]{RESET}")
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

                    # HIBP information
                    if finding.get("pwned"):
                        print(
                            f"     {MAGENTA}pwned: yes ({finding.get('pwned_count', 0):,} times){RESET}"
                        )
                    if finding.get("valid") is not None:
                        print(f"     valid: {finding['valid']}")
                    if finding.get("expired") is not None:
                        print(f"     expired: {finding['expired']}")

        # HIBP statistics
        if hibp_stats and hibp_stats.get("total_pwned_found", 0) > 0:
            print(f"\n{CYAN}HIBP STATISTICS{RESET}")
            print(f"{BLUE}{'-' * 40}{RESET}")
            print(f"passwords checked: {hibp_stats.get('total_passwords_checked', 0)}")
            print(f"pwned passwords found: {hibp_stats.get('total_pwned_found', 0)}")
            print(f"api errors: {hibp_stats.get('api_errors', 0)}")
            print(f"avg response time: {hibp_stats.get('average_response_time', 0)}s")

            if hibp_stats.get("pwned_passwords"):
                print("\nmost recent pwned passwords:")
                for p in hibp_stats["pwned_passwords"][-3:]:  # show last 3
                    print(
                        f"  {MAGENTA}•{RESET} {p['password']}: found in {p['count']:,} breaches"
                    )

        print(f"\nscan completed in {scan_time:.2f} seconds")

    @staticmethod
    def save_text_report(
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
        output_path: str,
        hibp_stats: Optional[Dict] = None,
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

            # count by severity
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            for finding in findings:
                sev = finding.get("severity", "low").lower()
                if sev in severity_counts:
                    severity_counts[sev] += 1

            f.write("SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"critical: {severity_counts['critical']}\n")
            f.write(f"high: {severity_counts['high']}\n")
            f.write(f"medium: {severity_counts['medium']}\n")
            f.write(f"low: {severity_counts['low']}\n\n")

            f.write("DETAILED FINDINGS\n")
            f.write("-" * 80 + "\n\n")

            for idx, finding in enumerate(findings, 1):
                f.write(f"[{idx}] {finding.get('severity', 'unknown').upper()}\n")
                f.write(f"    file: {finding.get('file', 'unknown')}\n")
                f.write(f"    line: {finding.get('line', 0)}\n")
                f.write(f"    type: {finding.get('type', 'unknown')}\n")
                if finding.get("variable"):
                    f.write(f"    variable: {finding['variable']}\n")
                f.write(f"    value: {finding.get('value', '')}\n")

                # HIBP information
                if finding.get("pwned"):
                    f.write(
                        f"    pwned: yes ({finding.get('pwned_count', 0):,} times)\n"
                    )

                # additional fields
                for key in ["service", "algorithm", "valid", "expired"]:
                    if key in finding:
                        f.write(f"    {key}: {finding[key]}\n")

                f.write("-" * 60 + "\n")

            # HIBP statistics
            if hibp_stats and hibp_stats.get("total_pwned_found", 0) > 0:
                f.write("\n" + "=" * 80 + "\n")
                f.write("HIBP STATISTICS\n")
                f.write("=" * 80 + "\n\n")
                f.write(
                    f"passwords checked: {hibp_stats.get('total_passwords_checked', 0)}\n"
                )
                f.write(
                    f"pwned passwords found: {hibp_stats.get('total_pwned_found', 0)}\n"
                )
                f.write(f"api errors: {hibp_stats.get('api_errors', 0)}\n")
                f.write(
                    f"avg response time: {hibp_stats.get('average_response_time', 0)}s\n\n"
                )

                if hibp_stats.get("pwned_passwords"):
                    f.write("pwned passwords:\n")
                    for p in hibp_stats["pwned_passwords"]:
                        f.write(
                            f"  • {p['password']}: found in {p['count']:,} breaches\n"
                        )
