"""
test_full_scan.py - integration tests
"""

import os
import tempfile

from core.file_handler import get_files
from core.scanner import Scanner


class TestFullScan:
    """integration tests for full scan workflow"""

    def setup_method(self):
        self.scanner = Scanner()
        self.temp_dir = tempfile.mkdtemp()
        self.create_test_files()

    def teardown_method(self):
        import shutil

        shutil.rmtree(self.temp_dir)

    def create_test_files(self):
        """create test files with various secrets"""

        # python file with secrets
        py_content = """
import os

# this should be detected
api_key = "AKIAIOSFODNN7EXAMPLE"
password = "supersecret123"

# this should be ignored
db_pass = os.getenv("DB_PASSWORD")
"""
        with open(os.path.join(self.temp_dir, "test.py"), "w") as f:
            f.write(py_content)

        # dockerfile with secrets
        docker_content = """
FROM alpine:latest
ENV API_KEY=sk_live_1234567890123456
RUN curl -u user:pass https://example.com
"""
        with open(os.path.join(self.temp_dir, "Dockerfile"), "w") as f:
            f.write(docker_content)

        # json with secrets
        json_content = """
{
  "api_key": "AIzaSyD-xxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "password": "secret123"
}
"""
        with open(os.path.join(self.temp_dir, "config.json"), "w") as f:
            f.write(json_content)

    def test_full_scan(self):
        """test scanning all files"""
        files = get_files(self.temp_dir)
        all_findings = []

        for file_path in files:
            findings = self.scanner.scan_file(file_path, enable_entropy=True)
            all_findings.extend(findings)

        # should find multiple secrets
        assert len(all_findings) >= 3

        # check for different types
        types = [f["type"] for f in all_findings]
        assert "variable_assignment" in types
        assert "env_variable" in types or "api_key" in types

    def test_scan_with_validation(self):
        """test scan with validation enabled"""
        files = get_files(self.temp_dir)

        # this shouldn't crash even without real validation
        for file_path in files:
            findings = self.scanner.scan_file(
                file_path, enable_entropy=True, validate=True
            )
            # just ensure it runs
            assert isinstance(findings, list)
