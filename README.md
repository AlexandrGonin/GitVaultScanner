# gitvaultscanner

a static analysis tool for finding hardcoded secrets, api keys, and credentials in code repositories and docker images.

## features

- scan github repositories
- scan local directories
- scan docker images
- detect various secret types:
  - api keys (aws, github, slack, etc.)
  - database connection strings
  - passwords and tokens
  - jwt tokens
  - private keys
- entropy-based detection for custom secrets
- validate found secrets (aws keys, jwt expiry)
- check passwords against have i been pwned
- multiple output formats: console, json, sarif, html

## installation

```bash
# clone the repository
git clone https://github.com/gitvaultscanner/gitvaultscanner.git
cd gitvaultscanner

# create virtual environment
python -m venv venv
source venv/bin/activate  # on windows: venv\scripts\activate

# install dependencies
pip install -r requirements.txt
