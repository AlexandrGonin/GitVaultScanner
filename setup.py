"""
setup.py - installation script for gitvaultscanner
"""

from setuptools import find_packages, setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [
        line.strip() for line in fh if line.strip() and not line.startswith("#")
    ]

setup(
    name="gitvaultscanner",
    version="1.0.0",
    author="gitvaultscanner",
    description="scanner for hardcoded secrets in code and docker images",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/gitvaultscanner/gitvaultscanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "gitvaultscanner=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "config": ["*.yaml", "*.conf"],
        "reporters": ["templates/*.html"],
    },
)
