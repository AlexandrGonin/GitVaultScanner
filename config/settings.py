"""
settings.py - configuration management
"""

import os
from typing import Any, Dict, Optional

import yaml

DEFAULT_CONFIG: Dict[str, Any] = {
    "extensions": [
        ".py",
        ".js",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".c",
        ".cpp",
        ".cs",
        ".rs",
    ],
    "entropy_threshold": 4.2,
    "min_secret_length": 8,
    "max_entropy_length": 200,
    "binary_min_string_length": 8,
    "enable_hibp": False,
    "validate_aws": False,
    "validate_jwt": False,
    "hibp_timeout": 5,
    "aws_validate_mode": "dry_run",
    "skip_dirs": [
        ".git",
        "__pycache__",
        "node_modules",
        "venv",
        "env",
        ".venv",
        ".env",
        "dist",
        "build",
        ".idea",
        ".vscode",
        "coverage",
        "htmlcov",
        ".pytest_cache",
        ".tox",
        "__pycache__",
    ],
    "patterns_file": None,
}


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    load configuration from file
    returns config dict
    """
    config = DEFAULT_CONFIG.copy()

    if config_path is not None and os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                if config_path.endswith((".yaml", ".yml")):
                    user_config = yaml.safe_load(f)
                else:
                    import json

                    user_config = json.load(f)

            if user_config is not None and isinstance(user_config, dict):
                config.update(user_config)

        except Exception as e:
            print(f"warning: could not load config from {config_path}: {e}")

    return config


def get_config_value(config: Dict[str, Any], key: str, default: Any = None) -> Any:
    """get a configuration value with fallback"""
    return config.get(key, default)
