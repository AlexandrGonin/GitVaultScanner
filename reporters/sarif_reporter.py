"""
sarif_reporter.py - sarif format for github security scanning
"""

import json
from datetime import datetime
from typing import Any, Dict, List


class SarifReporter:
    """reporter for sarif output (static analysis results interchange format)"""

    @staticmethod
    def save_report(
        findings: List[Dict[str, Any]],
        target_name: str,
        scan_time: float,
        scan_type: str,
        output_path: str,
    ):
        """save findings as sarif file"""

        sarif_log = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "gitvaultscanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/gitvaultscanner",
                            "rules": SarifReporter._create_rules(findings),
                        }
                    },
                    "results": SarifReporter._create_results(findings),
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now().isoformat(),
                            "endTimeUtc": datetime.now().isoformat(),
                        }
                    ],
                }
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=2)

    @staticmethod
    def _create_rules(findings: List[Dict[str, Any]]) -> List[Dict]:
        """create sarif rules from findings"""
        rules = []
        rule_ids = set()

        for f in findings:
            rule_id = f.get("type", "unknown")
            if rule_id in rule_ids:
                continue

            rule_ids.add(rule_id)

            severity = f.get("severity", "warning")
            if severity == "critical":
                level = "error"
            elif severity == "high":
                level = "error"
            elif severity == "medium":
                level = "warning"
            else:
                level = "note"

            rules.append(
                {
                    "id": rule_id,
                    "name": f"secret-{rule_id}",
                    "shortDescription": {"text": f"Hardcoded {rule_id} detected"},
                    "fullDescription": {
                        "text": f"Found a potential hardcoded {rule_id} which could lead to credential exposure"
                    },
                    "defaultConfiguration": {"level": level},
                    "helpUri": "https://github.com/gitvaultscanner/docs",
                    "properties": {"tags": ["security", "secrets", rule_id]},
                }
            )

        return rules

    @staticmethod
    def _create_results(findings: List[Dict[str, Any]]) -> List[Dict]:
        """create sarif results from findings"""
        results = []

        for idx, f in enumerate(findings):
            file_path = f.get("file", "unknown")
            line = f.get("line", 1)

            result = {
                "ruleId": f.get("type", "unknown"),
                "ruleIndex": 0,
                "message": {
                    "text": f"Found {f.get('type', 'secret')}: {f.get('value', '')[:50]}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path},
                            "region": {"startLine": line, "startColumn": 1},
                        }
                    }
                ],
                "partialFingerprints": {"primaryLocationLineHash": f"hash-{idx}"},
            }

            # add severity as property
            result["properties"] = {
                "severity": f.get("severity", "medium"),
                "security-severity": SarifReporter._severity_to_score(
                    f.get("severity", "medium")
                ),
            }

            results.append(result)

        return results

    @staticmethod
    def _severity_to_score(severity: str) -> str:
        """convert severity to cvss-like score"""
        scores = {"critical": "9.0", "high": "7.5", "medium": "5.0", "low": "2.5"}
        return scores.get(severity.lower(), "5.0")
