"""
exceptions.py - custom exceptions for the scanner
"""


class ScannerException(Exception):
    """base exception for scanner errors"""

    pass


class GitCloneError(ScannerException):
    """raised when git clone fails"""

    pass


class DockerPullError(ScannerException):
    """raised when docker pull fails"""

    pass


class ConfigError(ScannerException):
    """raised when configuration is invalid"""

    pass


class ParserError(ScannerException):
    """raised when file parsing fails"""

    pass


class ValidationError(ScannerException):
    """raised when secret validation fails"""

    pass
