"""
test_detectors.py - unit tests for detectors
"""

from detectors.api_key_detector import ApiKeyDetector
from detectors.jwt_detector import JwtDetector
from detectors.password_detector import PasswordDetector


class TestApiKeyDetector:
    """test api key detector"""

    def setup_method(self):
        self.detector = ApiKeyDetector()

    def test_detect_aws_key(self):
        """test detection of aws key"""
        line = 'aws_access_key = "AKIAIOSFODNN7EXAMPLE"'
        findings = self.detector.detect(line, "test.py", 1)

        assert len(findings) > 0
        assert findings[0]["service"] == "aws"
        assert findings[0]["severity"] == "high"

    def test_detect_github_token(self):
        """test detection of github token"""
        line = 'github_token = "ghp_123456789012345678901234567890123456"'
        findings = self.detector.detect(line, "test.py", 1)

        assert len(findings) > 0
        assert findings[0]["service"] == "github"

    def test_ignore_fake_keys(self):
        """test that fake/placeholder keys are ignored"""
        line = 'api_key = "your-api-key-here"'
        findings = self.detector.detect(line, "test.py", 1)

        assert len(findings) == 0


class TestJwtDetector:
    """test jwt detector"""

    def setup_method(self):
        self.detector = JwtDetector()

    def test_detect_jwt(self):
        """test detection of jwt token"""
        line = 'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"'
        findings = self.detector.detect(line, "test.py", 1)

        assert len(findings) > 0
        assert findings[0]["type"] == "jwt_token"

    def test_detect_authorization_header(self):
        """test detection in authorization header"""
        line = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = self.detector.detect(line, "test.py", 1)

        assert len(findings) > 0


class TestPasswordDetector:
    """test password detector"""

    def setup_method(self):
        self.detector = PasswordDetector()

    def test_detect_password_assignment(self):
        """test detection of password assignment"""
        line = 'password = "supersecret123"'
        findings = self.detector.detect(line, "test.py", 1)

        assert len(findings) > 0
        assert findings[0]["type"] == "password"

    def test_detect_connection_string(self):
        """test detection in connection string"""
        line = "postgresql://user:pass123@localhost:5432/db"
        findings = self.detector.detect(line, "test.py", 1)

        assert len(findings) > 0
        assert findings[0]["subtype"] == "postgres_pwd"

    def test_weak_password_medium_severity(self):
        """test that weak passwords get medium severity"""
        line = 'password = "password123"'
        findings = self.detector.detect(line, "test.py", 1)

        assert len(findings) > 0
        assert findings[0]["severity"] == "medium"
