# makefile for gitvaultscanner
.PHONY: help install test lint clean run docker-test

help:
	@echo "available targets:"
	@echo "  install     install dependencies"
	@echo "  test        run tests"
	@echo "  clean       clean temporary files"
	@echo "  run         run scanner on current directory"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt 2>/dev/null || true

test:
	pip install -e .
	pytest tests/ -v --cov=core --cov=parsers --cov=detectors
	rm -rf gitvaultscanner.egg-info/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.log" -delete
	find . -type f -name "*.html" -delete
	find . -type f -name "*.json" -delete
	find . -type f -name "*.coverage" -delete
	find . -type f -name "*.sarif" -delete
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf reports/
	rm -rf gitvaultscanner.egg-info/

run:
	python main.py --dir .
