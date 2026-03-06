"""
test_parsers.py - unit tests for parsers
"""

import os
import tempfile

from parsers.docker_parser import DockerParser
from parsers.source_code_parser import SourceCodeParser


class TestSourceCodeParser:
    """test source code parser"""

    def setup_method(self):
        self.parser = SourceCodeParser()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        import shutil

        shutil.rmtree(self.temp_dir)

    def create_test_file(self, content: str, filename: str = "test.py"):
        """create a test file with given content"""
        file_path = os.path.join(self.temp_dir, filename)
        with open(file_path, "w") as f:
            f.write(content)
        return file_path

    def test_detect_api_key(self):
        """test detection of api key in code"""
        content = 'api_key = "AKIAIOSFODNN7EXAMPLE"\n'
        file_path = self.create_test_file(content)

        findings = self.parser.parse(file_path)
        assert len(findings) > 0
        assert findings[0]["type"] == "variable_assignment"

    def test_ignore_comments(self):
        """test that comments are ignored"""
        content = '# api_key = "secret"\n'
        file_path = self.create_test_file(content)

        findings = self.parser.parse(file_path)
        assert len(findings) == 0

    def test_ignore_env_vars(self):
        """test that environment variable references are ignored"""
        content = 'api_key = os.getenv("API_KEY")\n'
        file_path = self.create_test_file(content)

        findings = self.parser.parse(file_path)
        assert len(findings) == 0


class TestDockerParser:
    """test dockerfile parser"""

    def setup_method(self):
        self.parser = DockerParser()
        self.temp_dir = tempfile.mkdtemp()

    def teardown_method(self):
        import shutil

        shutil.rmtree(self.temp_dir)

    def create_dockerfile(self, content: str):
        """create a test dockerfile"""
        file_path = os.path.join(self.temp_dir, "Dockerfile")
        with open(file_path, "w") as f:
            f.write(content)
        return file_path

    def test_detect_env_secret(self):
        """test detection of secret in ENV instruction"""
        content = "ENV API_KEY=sk_live_1234567890123456\n"
        file_path = self.create_dockerfile(content)

        findings = self.parser.parse(file_path)
        assert len(findings) > 0
        assert findings[0]["type"] == "env_variable"

    def test_detect_run_secret(self):
        """test detection of secret in RUN command"""
        content = "RUN curl -u user:password https://example.com\n"
        file_path = self.create_dockerfile(content)

        findings = self.parser.parse(file_path)
        assert len(findings) > 0
        assert findings[0]["type"] == "curl_with_auth"
