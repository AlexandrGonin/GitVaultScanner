# gitvaultscanner usage guide

## installation

```bash
# clone repository
git clone https://github.com/gitvaultscanner/gitvaultscanner.git
cd gitvaultscanner

# create virtual environment
python -m venv venv
source venv/bin/activate  # on windows: venv\scripts\activate

# install dependencies
pip install -r requirements.txt

basic usage
scan a github repository
bash

python main.py --repo https://github.com/user/repo

scan a local directory
bash

python main.py --dir /path/to/code

scan a docker image
bash

python main.py --docker ubuntu:latest

advanced options
output formats
bash

# json output
python main.py --dir /path/to/code --format json --output results.json

# sarif output (github security)
python main.py --repo https://github.com/user/repo --format sarif --output results.sarif

# html report
python main.py --dir /path/to/code --format html --output report.html

detection options
bash

# enable entropy-based detection
python main.py --dir /path/to/code --entropy

# validate found secrets (aws keys, jwt tokens)
python main.py --repo https://github.com/user/repo --validate

# check passwords against have i been pwned
python main.py --dir /path/to/code --hibp

file filtering
bash

# scan only specific file types
python main.py --dir /path/to/code --extensions .py .js .java

# verbose output
python main.py --dir /path/to/code --verbose

configuration file

create a custom config file:
yaml

# custom_config.yaml
extensions:
  - .py
  - .js
  - .go

entropy_threshold: 4.5
min_secret_length: 10

patterns:
  - name: custom_pattern
    pattern: 'CUSTOM-[A-Z0-9]{20}'
    severity: high

use it:
bash

python main.py --dir /path/to/code --config custom_config.yaml

exit codes

    0: scan completed, no high-risk secrets

    1: scan completed, high-risk secrets found

    2: scanner error (configuration, git clone, etc.)

    3: unexpected error

integration with ci/cd
github actions
yaml

name: secret scan
on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: run gitvaultscanner
        run: |
          python main.py --dir . --format sarif --output results.sarif
      - name: upload sarif
        uses: github/codeql-action/upload-sarif@v1
        with:
          sarif_file: results.sarif

gitlab ci
yaml

secret-scan:
  script:
    - python main.py --dir . --format json --output gl-secrets.json
  artifacts:
    reports:
      secret_detection: gl-secrets.json

performance optimization

    use --extensions to limit file types

    use shallow clones with --depth 1 for large repos

    benchmark with scripts/benchmark.py
