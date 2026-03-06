"""
aws_key_validator.py - validate aws access keys
"""

import re
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


class AwsKeyValidator:
    """validate aws access keys by attempting sts.get_caller_identity"""

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.validate_mode = self.config.get("aws_validate_mode", "dry_run")

    def validate(
        self, access_key: str, secret_key: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        validate aws credentials
        returns dict with validation results
        """
        result = {"valid": False, "active": False, "service": None, "error": None}

        # if only access key provided, try to find secret in context
        if secret_key is None:
            # can't validate without secret
            result["error"] = "secret_key_required"
            return result

        try:
            # attempt to create sts client
            sts = boto3.client(
                "sts",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name="us-east-1",
            )

            # try to get caller identity
            identity = sts.get_caller_identity()

            result["valid"] = True
            result["active"] = True
            result["account"] = identity.get("Account")
            result["user_id"] = identity.get("UserId")
            result["arn"] = identity.get("Arn")

            # determine service based on arn
            if ":iam::" in result["arn"]:
                result["service"] = "iam_user"
            elif ":role/" in result["arn"]:
                result["service"] = "iam_role"

        except ClientError as e:
            # credentials are invalid or inactive
            result["error"] = str(e)
            if "AccessDenied" in str(e):
                result["valid"] = True  # key exists but lacks permissions
                result["active"] = False
            elif "InvalidClientTokenId" in str(e):
                result["valid"] = False
                result["active"] = False

        except NoCredentialsError:
            result["error"] = "no_credentials"
        except Exception as e:
            result["error"] = str(e)

        return result

    def extract_secret_from_context(self, line: str) -> Optional[str]:
        """try to extract aws secret key from same line as access key"""
        # look for 40-char base64-like string
        secret_pattern = re.compile(r"[A-Za-z0-9/+=]{40}")
        match = secret_pattern.search(line)
        return match.group(0) if match else None
