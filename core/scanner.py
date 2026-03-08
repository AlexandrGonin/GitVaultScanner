"""
scanner.py - main scanning orchestration class
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from config.settings import load_config
from detectors.api_key_detector import ApiKeyDetector
from detectors.hibp_checker import HibpChecker
from detectors.jwt_detector import JwtDetector
from detectors.password_detector import PasswordDetector
from parsers.binary_parser import BinaryParser
from parsers.ci_cd_parser import CiCdParser
from parsers.docker_parser import DockerParser
from parsers.entropy_analyzer import EntropyAnalyzer
from parsers.source_code_parser import SourceCodeParser
from parsers.terraform_parser import TerraformParser
from validators.aws_key_validator import AwsKeyValidator
from validators.jwt_validator import JwtValidator


class Scanner:
    """main scanner class that coordinates all detection methods"""

    def __init__(self, config_path: Optional[str] = None):
        """initialize scanner with configuration"""
        self.config = load_config(config_path)

        # initialize parsers
        self.source_parser = SourceCodeParser(self.config)
        self.docker_parser = DockerParser(self.config)
        self.binary_parser = BinaryParser(self.config)
        self.ci_cd_parser = CiCdParser(self.config)
        self.terraform_parser = TerraformParser(self.config)
        self.entropy_analyzer = EntropyAnalyzer(self.config)

        # initialize detectors
        self.api_detector = ApiKeyDetector(self.config)
        self.jwt_detector = JwtDetector(self.config)
        self.password_detector = PasswordDetector(self.config)

        # initialize optional components
        # HIBP checker - создаем всегда, он будет использоваться только если передан флаг hibp
        self.hibp_checker = HibpChecker(self.config)

        # validators
        validate_aws = self.config.get("validate_aws", False)
        self.aws_validator = AwsKeyValidator(self.config) if validate_aws else None

        validate_jwt = self.config.get("validate_jwt", False)
        self.jwt_validator = JwtValidator(self.config) if validate_jwt else None

    def scan_file(
        self,
        file_path: str,
        enable_entropy: bool = False,
        validate: bool = False,
        hibp: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        scan a single file using all available parsers
        returns list of findings
        """
        if not os.path.isfile(file_path):
            return []

        findings: List[Dict[str, Any]] = []
        file_ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path).lower()

        # determine which parsers to use based on file type
        if file_name in ["dockerfile", "containerfile"] or file_ext in [".dockerfile"]:
            findings.extend(self.docker_parser.parse(file_path))

        elif file_ext in [".tf", ".tfvars"]:
            findings.extend(self.terraform_parser.parse(file_path))

        elif file_ext in [".yml", ".yaml"] and ".github/" in file_path.replace(
            "\\", "/"
        ):
            findings.extend(self.ci_cd_parser.parse(file_path))

        elif self._is_binary_file(file_path):
            findings.extend(self.binary_parser.parse(file_path))

        else:
            # source code file - use source parser
            findings.extend(self.source_parser.parse(file_path))

        # run entropy analysis if enabled
        if enable_entropy:
            entropy_findings = self.entropy_analyzer.analyze(file_path)
            findings.extend(entropy_findings)

        # validate findings if enabled
        if validate and findings:
            findings = self._validate_findings(findings)

        # check against hibp if enabled - ТЕПЕРЬ ВСЕГДА ПРОВЕРЯЕМ ПО ФЛАГУ
        if hibp and findings and self.hibp_checker is not None:
            findings = self._check_hibp(findings)

        return findings

    def _is_binary_file(self, file_path: str) -> bool:
        """check if file is binary"""
        try:
            with open(file_path, "tr") as f:
                f.read(1024)
                return False
        except UnicodeDecodeError:
            return True

    def _validate_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """run validation on findings"""
        for finding in findings:
            finding_type = finding.get("type", "")
            value = finding.get("value")

            if value is None:
                continue

            if finding_type == "aws_key" and self.aws_validator is not None:
                finding["valid"] = self.aws_validator.validate(str(value))
            elif finding_type == "jwt_token" and self.jwt_validator is not None:
                expiry = self.jwt_validator.get_expiry(str(value))
                if expiry is not None:
                    finding["expires_at"] = expiry
                    finding["expired"] = expiry < datetime.now().timestamp()

        return findings

    def _check_hibp(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """check passwords against have i been pwned"""
        if self.hibp_checker is None:
            return findings

        for finding in findings:
            if finding.get("type") == "password":
                value = finding.get("value")
                if value is not None:
                    pwned_count = self.hibp_checker.check_password(str(value))
                    if pwned_count > 0:
                        finding["pwned"] = True
                        finding["pwned_count"] = pwned_count
                        finding["severity"] = "critical"

        return findings
