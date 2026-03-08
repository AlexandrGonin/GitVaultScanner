"""
html_reporter.py - html report generation
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional


class HtmlReporter:
    """reporter for html output"""

    @staticmethod
    def save_report(
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
        output_path: str,
        hibp_stats: Optional[Dict] = None,
    ):
        """save findings as html file with HIBP statistics"""

        # count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f.get("severity", "low").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["low"] += 1

        # group by file
        files = {}
        for f in findings:
            file_path = f.get("file", "unknown")
            if file_path not in files:
                files[file_path] = []
            files[file_path].append(f)

        # generate html
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>gitvaultscanner report - {target_name}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 20px; }}
        h1, h2 {{ color: #333; margin-top: 0; }}
        h1 {{ border-bottom: 2px solid #eee; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .stat {{ padding: 20px; border-radius: 8px; color: white; text-align: center; }}
        .stat.critical {{ background: #7b1e3a; }}
        .stat.high {{ background: #c62828; }}
        .stat.medium {{ background: #f57c00; }}
        .stat.low {{ background: #388e3c; }}
        .stat .count {{ font-size: 36px; font-weight: bold; }}
        .stat .label {{ font-size: 14px; opacity: 0.9; }}
        .hibp-stats {{ background: #e3f2fd; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #2196f3; }}
        .hibp-stats h3 {{ margin-top: 0; color: #1976d2; }}
        .hibp-stats .stat-row {{ display: flex; justify-content: space-between; margin: 10px 0; }}
        .hibp-stats .stat-item {{ flex: 1; text-align: center; }}
        .hibp-stats .stat-value {{ font-size: 24px; font-weight: bold; color: #1976d2; }}
        .hibp-stats .stat-label {{ font-size: 12px; color: #666; }}
        .file-section {{ margin: 20px 0; border: 1px solid #ddd; border-radius: 8px; }}
        .file-header {{ background: #f8f9fa; padding: 15px; border-bottom: 1px solid #ddd; font-weight: bold; cursor: pointer; display: flex; justify-content: space-between; }}
        .file-header:hover {{ background: #e9ecef; }}
        .file-findings {{ padding: 15px; display: none; }}
        .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid; background: #f8f9fa; }}
        .finding.critical {{ border-left-color: #7b1e3a; }}
        .finding.high {{ border-left-color: #c62828; }}
        .finding.medium {{ border-left-color: #f57c00; }}
        .finding.low {{ border-left-color: #388e3c; }}
        .finding .line {{ color: #666; font-size: 12px; }}
        .finding .type {{ font-weight: bold; }}
        .finding .value {{ font-family: monospace; background: white; padding: 5px; border-radius: 4px; margin-top: 5px; overflow-x: auto; }}
        .finding .pwned {{ color: #7b1e3a; font-weight: bold; margin-top: 5px; padding: 5px; background: #ffebee; border-radius: 4px; }}
        .metadata {{ color: #666; font-size: 12px; margin-top: 20px; padding-top: 10px; border-top: 1px solid #eee; }}
        .severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }}
        .severity-badge.critical {{ background: #7b1e3a; }}
        .severity-badge.high {{ background: #c62828; }}
        .severity-badge.medium {{ background: #f57c00; }}
        .severity-badge.low {{ background: #388e3c; }}
        .toggle-all {{ margin: 10px 0; padding: 8px 16px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }}
        .toggle-all:hover {{ background: #0056b3; }}
        .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; text-align: center; color: #999; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>GitVaultScanner report: {target_name}</h1>

        <div class="metadata">
            <strong>scan type:</strong> {scan_type}<br>
            <strong>scan date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br>
            <strong>scan duration:</strong> {scan_time:.2f} seconds<br>
            <strong>total findings:</strong> {len(findings)}
        </div>

        <div class="summary">
            <div class="stat critical">
                <div class="count">{severity_counts["critical"]}</div>
                <div class="label">critical</div>
            </div>
            <div class="stat high">
                <div class="count">{severity_counts["high"]}</div>
                <div class="label">high</div>
            </div>
            <div class="stat medium">
                <div class="count">{severity_counts["medium"]}</div>
                <div class="label">medium</div>
            </div>
            <div class="stat low">
                <div class="count">{severity_counts["low"]}</div>
                <div class="label">low</div>
            </div>
        </div>
"""

        # HIBP statistics - ВСЕГДА показываем секцию, если HIBP использовался
        if hibp_stats is not None:
            html += f"""
        <div class="hibp-stats">
            <h3>Have I Been Pwned (HIBP) Statistics</h3>
            <div class="stat-row">
                <div class="stat-item">
                    <div class="stat-value">{hibp_stats.get("total_passwords_checked", 0)}</div>
                    <div class="stat-label">passwords checked</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{hibp_stats.get("total_pwned_found", 0)}</div>
                    <div class="stat-label">pwned found</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{hibp_stats.get("api_errors", 0)}</div>
                    <div class="stat-label">API errors</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">{hibp_stats.get("average_response_time", 0)}s</div>
                    <div class="stat-label">avg response</div>
                </div>
            </div>
"""
            if (
                hibp_stats.get("pwned_passwords")
                and len(hibp_stats["pwned_passwords"]) > 0
            ):
                html += """
            <p><strong>Compromised passwords found:</strong></p>
            <ul>
"""
                for p in hibp_stats["pwned_passwords"][-5:]:  # last 5
                    html += f"""
                <li><strong>{p["password"]}</strong> - found in {p["count"]:,} breaches</li>
"""
                html += """
            </ul>
"""
            else:
                html += """
            <p>✅ No compromised passwords found in this scan.</p>
"""
            html += """
        </div>
"""

        html += """
        <button class="toggle-all" onclick="toggleAll()">Toggle all files</button>

        <div id="files">
"""

        if not files:
            html += """
        <p style="text-align: center; padding: 40px; color: #999;">No files with findings</p>
"""
        else:
            for file_path, file_findings in files.items():
                rel_path = os.path.basename(file_path)
                file_critical = sum(
                    1 for f in file_findings if f.get("severity") == "critical"
                )
                file_high = sum(1 for f in file_findings if f.get("severity") == "high")

                badge = ""
                if file_critical > 0:
                    badge = f'<span style="background: #7b1e3a; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px;">{file_critical} critical</span>'
                elif file_high > 0:
                    badge = f'<span style="background: #c62828; color: white; padding: 2px 8px; border-radius: 12px; font-size: 11px;">{file_high} high</span>'

                html += f"""
            <div class="file-section">
                <div class="file-header" onclick="toggleFile(this)">
                    <span>{rel_path} ({len(file_findings)} findings)</span>
                    {badge}
                </div>
                <div class="file-findings">
"""
                for f in file_findings:
                    sev = f.get("severity", "low").lower()
                    html += f"""
                    <div class="finding {sev}">
                        <div>
                            <span class="severity-badge {sev}">{sev}</span>
                            <span class="type">{f.get("type", "unknown")}</span>
                        </div>
                        <div class="line">line {f.get("line", 0)}</div>
"""
                    if f.get("variable"):
                        html += f"<div><strong>variable:</strong> {f['variable']}</div>"
                    html += f"""
                        <div class="value">{f.get("value", "")}</div>
"""
                    # HIBP information
                    if f.get("pwned"):
                        html += f'<div class="pwned">PWNED: found in {f.get("pwned_count", 0):,} data breaches</div>'

                    # additional fields
                    for key in ["service", "algorithm", "valid", "expired"]:
                        if key in f:
                            html += f"<div><strong>{key}:</strong> {f[key]}</div>"
                    html += """
                    </div>
"""
                html += """
                </div>
            </div>
"""

        html += """
        </div>

        <div class="footer">
            generated by gitvaultscanner • report contains security-sensitive information
        </div>
    </div>

    <script>
        function toggleFile(header) {
            const findings = header.nextElementSibling;
            findings.style.display = findings.style.display === 'block' ? 'none' : 'block';
        }

        function toggleAll() {
            const files = document.querySelectorAll('.file-findings');
            const anyHidden = Array.from(files).some(f => f.style.display !== 'block');
            files.forEach(f => f.style.display = anyHidden ? 'block' : 'none');
        }

        // open first file by default
        window.onload = function() {
            const firstFile = document.querySelector('.file-findings');
            if (firstFile) {
                firstFile.style.display = 'block';
            }
        }
    </script>
</body>
</html>
"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
