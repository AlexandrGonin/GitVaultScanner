# makefile for gitvaultscanner
.PHONY: help install test lint clean run docker-test

help:
	@echo "available targets:"
	@echo "  install     install dependencies"
	@echo "  test        run tests"
	@echo "  lint        run linter"
	@echo "  clean       clean temporary files"
	@echo "  run         run scanner on current directory"
	@echo "  docker-test test docker image scanning"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt 2>/dev/null || true

test:
	pytest tests/ -v --cov=core --cov=parsers --cov=detectors

lint:
	flake8 core/ parsers/ detectors/ utils/ reporters/
	black --check core/ parsers/ detectors/ utils/ reporters/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.log" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf reports/

run:
	python main.py --dir .

docker-test:
	python main.py --docker alpine:latest --output docker-report.json --format json
