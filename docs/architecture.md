# gitvaultscanner architecture

## overview

gitvaultscanner is a modular static analysis tool for detecting hardcoded secrets in code, docker images, and infrastructure configurations.

## core components

### 1. scanner (core/scanner.py)
- orchestrates the scanning process
- selects appropriate parsers based on file type
- manages configuration and validation

### 2. parsers (parsers/)
each parser handles specific file types:
- `source_code_parser.py`: general source code files
- `docker_parser.py`: dockerfiles and container configs
- `binary_parser.py`: binary files (extracts strings)
- `ci_cd_parser.py`: ci/cd pipeline configs
- `terraform_parser.py`: terraform infrastructure code
- `entropy_analyzer.py`: entropy-based detection

### 3. detectors (detectors/)
specialized detection modules:
- `regex_detector.py`: pattern-based detection
- `api_key_detector.py`: service-specific api keys
- `jwt_detector.py`: jwt token detection
- `password_detector.py`: password detection in various contexts
- `hibp_checker.py`: have i been pwned integration

### 4. validators (validators/)
validate found secrets:
- `aws_key_validator.py`: check aws key validity
- `jwt_validator.py`: validate jwt structure and expiry

### 5. reporters (reporters/)
multiple output formats:
- `console_reporter.py`: terminal output
- `json_reporter.py`: structured json
- `sarif_reporter.py`: sarif format for github security
- `html_reporter.py`: standalone html report

## data flow

1. user provides target (repo/dir/docker)
2. target is prepared (cloned/pulled/extracted)
3. files are collected with filtering
4. each file is passed to appropriate parsers
5. detectors analyze content
6. validators check findings (optional)
7. reporters generate output

## configuration

configuration is managed through:
- default settings in `config/settings.py`
- optional yaml config file
- command line arguments (override)

## extension points

new parsers should inherit from `BaseParser` and implement:
- `can_parse()`: determine if file is supported
- `parse()`: return list of findings

new detectors should implement:
- `detect()`: return findings from a line of text
