#!/usr/bin/env python3
"""
generate_test_data.py - generate test files with various secrets
"""

import argparse
import os
import random
import string


def random_string(length: int) -> str:
    """generate random string"""
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def generate_aws_key() -> str:
    """generate fake aws key"""
    return f"AKIA{random_string(16).upper()}"


def generate_github_token() -> str:
    """generate fake github token"""
    return f"ghp_{random_string(36)}"


def generate_test_file(file_path: str, content: str):
    """write content to file"""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w") as f:
        f.write(content)


def main():
    parser = argparse.ArgumentParser(
        description="generate test data for gitvaultscanner"
    )
    parser.add_argument(
        "--output",
        "-o",
        default="testing_data/malicious_samples",
        help="output directory",
    )
    parser.add_argument(
        "--count", "-c", type=int, default=10, help="number of test files to generate"
    )

    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    for i in range(args.count):
        # python file with secrets
        py_content = f'''#!/usr/bin/env python3
# test file {i} - contains fake secrets for testing

import os
import sys

# aws credentials
aws_key = "{generate_aws_key()}"
aws_secret = "{random_string(40)}"

# github token
github_token = "{generate_github_token()}"

# database connection
db_url = "postgresql://user:{random_string(12)}@localhost:5432/testdb"

# api key
api_key = "{random_string(32)}"

# this should be ignored
safe_key = os.getenv("SAFE_KEY")
'''

        file_name = f"test_{i:03d}.py"
        generate_test_file(os.path.join(args.output, file_name), py_content)

    # generate dockerfile
    docker_content = f"""FROM alpine:latest

# env with secret
ENV API_KEY={random_string(32)}
ENV DB_PASSWORD={random_string(16)}

# run with credentials
RUN curl -u admin:{random_string(12)} https://example.com/api

# copy with credentials (bad practice)
COPY --chown=user:pass . /app
"""
    generate_test_file(os.path.join(args.output, "Dockerfile.test"), docker_content)

    # generate terraform file
    tf_content = f'''resource "aws_db_instance" "test" {{
  identifier = "test-db"
  engine = "mysql"
  username = "admin"
  password = "{random_string(16)}"
  publicly_accessible = true
}}

resource "aws_iam_access_key" "test" {{
  user = "test-user"
  # missing pgp_key - will be flagged
}}
'''
    generate_test_file(os.path.join(args.output, "terraform.tf"), tf_content)

    print(f"generated {args.count + 3} test files in {args.output}")


if __name__ == "__main__":
    main()
