"""
terraform_parser.py - parser for terraform infrastructure as code
"""

import os
import re
from typing import Any, Dict, List, Optional

from parsers.base_parser import BaseParser


class TerraformParser(BaseParser):
    """parser for terraform files - finds secrets in infrastructure code"""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)

        # sensitive terraform resources
        self.sensitive_resources = [
            "aws_iam_access_key",
            "aws_db_instance",
            "aws_redshift_cluster",
            "aws_elasticache_cluster",
            "google_service_account_key",
            "azurerm_storage_account",
            "random_password",
            "random_string",
        ]

        # patterns for sensitive attributes
        self.sensitive_attributes = [
            "password",
            "secret",
            "private_key",
            "connection_string",
            "master_password",
            "access_key",
            "secret_key",
            "token",
        ]

        # patterns for hardcoded secrets
        self.hardcoded_pattern = re.compile(r'=\s*[\'"]([^\'"]{8,})[\'"]')

        # patterns for variable references
        self.var_ref_pattern = re.compile(r"\${?var\.([^}]+)}?")

        # patterns for data sources that might expose secrets
        self.sensitive_data_sources = [
            "aws_secretsmanager_secret_version",
            "aws_ssm_parameter",
            "vault_generic_secret",
        ]

    def can_parse(self, file_path: str) -> bool:
        """check if file is terraform configuration"""
        filename = os.path.basename(file_path)
        return filename.endswith((".tf", ".tfvars"))

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        """parse terraform file for secrets"""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return []

        lines = content.split("\n")
        in_resource = False
        current_resource = None

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # skip comments
            if stripped.startswith("#") or stripped.startswith("//"):
                continue

            # check for resource blocks
            resource_match = re.search(r'resource\s+"([^"]+)"\s+"[^"]+"', line)
            if resource_match:
                in_resource = True
                current_resource = resource_match.group(1)
            elif in_resource and stripped == "}":
                in_resource = False
                current_resource = None

            # check for sensitive resources
            if current_resource and current_resource in self.sensitive_resources:
                findings.extend(
                    self._check_sensitive_resource(
                        file_path, line_num, line, current_resource
                    )
                )

            # check for hardcoded secrets in attributes
            for attr in self.sensitive_attributes:
                if attr in line.lower():
                    value_match = self.hardcoded_pattern.search(line)
                    if value_match:
                        value = value_match.group(1)
                        if len(value) >= 8:
                            findings.append(
                                self._create_finding(
                                    file_path,
                                    line_num,
                                    "hardcoded_secret",
                                    value,
                                    severity="high",
                                    attribute=attr,
                                    resource=current_resource,
                                )
                            )

            # check for missing encryption
            if "aws_db_instance" in line and "storage_encrypted = false" in line:
                findings.append(
                    self._create_finding(
                        file_path,
                        line_num,
                        "unencrypted_db",
                        "storage_encrypted = false",
                        severity="medium",
                    )
                )

            # check for public exposure
            if "publicly_accessible = true" in line:
                findings.append(
                    self._create_finding(
                        file_path,
                        line_num,
                        "publicly_accessible",
                        "true",
                        severity="high",
                        resource=current_resource,
                    )
                )

        return findings

    def _check_sensitive_resource(
        self, file_path: str, line_num: int, line: str, resource: str
    ) -> List[Dict[str, Any]]:
        """check sensitive resource for specific issues"""
        findings = []

        # aws_iam_access_key specific checks
        if resource == "aws_iam_access_key":
            if "pgp_key" not in line and "secret" in line.lower():
                findings.append(
                    self._create_finding(
                        file_path,
                        line_num,
                        "unencrypted_aws_key",
                        "key without pgp encryption",
                        severity="high",
                    )
                )

        # aws_db_instance specific checks
        elif resource == "aws_db_instance":
            if "password" in line.lower() and "var." not in line:
                findings.append(
                    self._create_finding(
                        file_path,
                        line_num,
                        "db_password_hardcoded",
                        line.strip(),
                        severity="critical",
                    )
                )

        return findings

    def _check_tfvars(self, file_path: str) -> List[Dict[str, Any]]:
        """special handling for terraform variable files"""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return findings

        # tfvars files often contain actual values
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            if "=" in line and not line.strip().startswith("#"):
                parts = line.split("=", 1)
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    value = parts[1].strip().strip("\"'")

                    # check if this is a sensitive variable
                    if self._is_sensitive_var(var_name) and len(value) >= 8:
                        findings.append(
                            self._create_finding(
                                file_path,
                                line_num,
                                "tfvar_secret",
                                value,
                                severity="high",
                                variable=var_name,
                            )
                        )

        return findings

    def _is_sensitive_var(self, var_name: str) -> bool:
        """check if variable name suggests sensitive data"""
        sensitive = ["password", "secret", "token", "key", "pwd"]
        var_lower = var_name.lower()
        return any(s in var_lower for s in sensitive)
