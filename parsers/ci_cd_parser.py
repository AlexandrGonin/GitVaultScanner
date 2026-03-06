"""
ci_cd_parser.py - parser for ci/cd pipeline configurations
"""

import os
import re
from typing import Any, Dict, List, Optional, Union

import yaml

from parsers.base_parser import BaseParser


class CiCdParser(BaseParser):
    """parser for ci/cd files - finds secrets in pipeline configurations"""

    def __init__(self, config: Optional[Dict] = None):
        super().__init__(config)

        # patterns for dangerous commands in ci/cd
        self.dangerous_commands = [
            (re.compile(r"echo\s+\$?({?\w+}?)"), "echo_secret"),
            (re.compile(r"printenv"), "printenv"),
            (re.compile(r"set\s+-x"), "enable_trace"),
            (re.compile(r"curl.*?\$({?\w+}?)"), "curl_with_secret"),
            (re.compile(r"wget.*?\$({?\w+}?)"), "wget_with_secret"),
            (re.compile(r"--password\s+\$({?\w+}?)"), "password_in_arg"),
            (re.compile(r"--token\s+\$({?\w+}?)"), "token_in_arg"),
        ]

        # environment variable patterns
        self.env_var_pattern = re.compile(r"\$({?[A-Za-z_][A-Za-z0-9_]+}?)")

        # github actions specific patterns
        self.github_secrets = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")

        # gitlab ci specific patterns
        self.gitlab_vars = re.compile(r"\$CI_\w+")

    def can_parse(self, file_path: str) -> bool:
        """check if file is ci/cd configuration"""
        filename = os.path.basename(file_path).lower()

        # github actions
        if ".github/workflows/" in file_path.replace("\\", "/"):
            return filename.endswith((".yml", ".yaml"))

        # gitlab ci
        if filename in [".gitlab-ci.yml", ".gitlab-ci.yaml"]:
            return True

        # jenkins
        if filename == "jenkinsfile":
            return True

        return False

    def parse(self, file_path: str) -> List[Dict[str, Any]]:
        """parse ci/cd file for secrets"""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return []

        # try to parse as yaml for structured analysis
        try:
            data = yaml.safe_load(content)
            if isinstance(data, dict):
                findings.extend(self._parse_yaml_structure(file_path, data))
            elif isinstance(data, list):
                # handle list at root level
                for idx, item in enumerate(data):
                    if isinstance(item, dict):
                        findings.extend(
                            self._parse_yaml_structure(file_path, item, f"[{idx}]")
                        )
        except yaml.YAMLError:
            pass

        # scan raw content for secrets
        lines = content.split("\n")
        for line_num, line in enumerate(lines, 1):
            findings.extend(self._scan_line(file_path, line_num, line))

        return findings

    def _parse_yaml_structure(
        self, file_path: str, data: Union[Dict, List], path: str = ""
    ) -> List[Dict[str, Any]]:
        """recursively parse yaml structure for secrets"""
        findings = []

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # check for environment variables in steps
                if key in ["env", "environment", "with"] and isinstance(value, dict):
                    for env_key, env_value in value.items():
                        if isinstance(env_value, str) and self._is_potential_secret(
                            env_value
                        ):
                            findings.append(
                                self._create_finding(
                                    file_path,
                                    0,
                                    "env_variable",
                                    env_value,
                                    severity="medium",
                                    variable=env_key,
                                    yaml_path=current_path,
                                )
                            )

                # check for scripts that might leak secrets
                if key in ["run", "script"]:
                    if isinstance(value, str):
                        findings.extend(
                            self._scan_script(file_path, value, current_path)
                        )
                    elif isinstance(value, list):
                        for idx, cmd in enumerate(value):
                            if isinstance(cmd, str):
                                findings.extend(
                                    self._scan_script(
                                        file_path, cmd, f"{current_path}[{idx}]"
                                    )
                                )

                # recurse
                if isinstance(value, (dict, list)):
                    findings.extend(
                        self._parse_yaml_structure(file_path, value, current_path)
                    )

        elif isinstance(data, list):
            for idx, item in enumerate(data):
                if isinstance(item, (dict, list)):
                    findings.extend(
                        self._parse_yaml_structure(file_path, item, f"{path}[{idx}]")
                    )

        return findings

    def _scan_line(
        self, file_path: str, line_num: int, line: str
    ) -> List[Dict[str, Any]]:
        """scan a single line of ci/cd file"""
        findings = []

        # check for github secrets
        for match in self.github_secrets.finditer(line):
            secret_name = match.group(1)
            findings.append(
                self._create_finding(
                    file_path,
                    line_num,
                    "github_secret_reference",
                    secret_name,
                    severity="low",
                    context=line[:100],
                )
            )

        # check for environment variables
        for match in self.env_var_pattern.finditer(line):
            var_name = match.group(1).strip("{}")
            if self._is_sensitive_var(var_name):
                findings.append(
                    self._create_finding(
                        file_path,
                        line_num,
                        "sensitive_env_var",
                        var_name,
                        severity="medium",
                        context=line[:100],
                    )
                )

        # check for dangerous commands
        for pattern, finding_type in self.dangerous_commands:
            if pattern.search(line):
                findings.append(
                    self._create_finding(
                        file_path,
                        line_num,
                        finding_type,
                        line[:100],
                        severity="high",
                        command=line[:200],
                    )
                )

        return findings

    def _scan_script(
        self, file_path: str, script: str, location: str
    ) -> List[Dict[str, Any]]:
        """scan a script block for secrets"""
        findings = []
        lines = script.split("\n")

        for line_num, line in enumerate(lines, 1):
            # check for dangerous commands
            for pattern, finding_type in self.dangerous_commands:
                if pattern.search(line):
                    findings.append(
                        self._create_finding(
                            file_path,
                            line_num,
                            finding_type,
                            line[:100],
                            severity="high",
                            script_location=location,
                        )
                    )

        return findings

    def _is_potential_secret(self, value: str) -> bool:
        """check if string might be a secret"""
        # looks like a hardcoded secret
        if len(value) >= 16 and re.search(r"[^a-zA-Z0-9]", value):
            return True

        # looks like an api key
        if re.match(r"[A-Z0-9]{20,}", value):
            return True

        return False

    def _is_sensitive_var(self, var_name: str) -> bool:
        """check if variable name suggests sensitive data"""
        sensitive_patterns = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "key",
            "credential",
            "auth",
            "private",
            "access",
        ]

        var_lower = var_name.lower()
        return any(p in var_lower for p in sensitive_patterns)
