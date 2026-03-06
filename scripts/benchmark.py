#!/usr/bin/env python3
"""
benchmark.py - performance benchmarking for gitvaultscanner
"""

import argparse
import os
import tempfile
import time

from core.file_handler import get_files
from core.scanner import Scanner


def create_large_test_dir(size_mb: int = 100) -> str:
    """create a directory with dummy files for benchmarking"""
    temp_dir = tempfile.mkdtemp(prefix="gvs_bench_")

    # estimate: each file ~10KB
    num_files = (size_mb * 1024 * 1024) // (10 * 1024)

    print(f"creating {num_files} test files...")

    for i in range(num_files):
        file_path = os.path.join(temp_dir, f"file_{i:04d}.py")
        with open(file_path, "w") as f:
            # write some python code
            f.write(f"""# file {i}
import os

def test_function():
    x = 42
    return x

# comment
API_KEY = "test_key_{i}"

# safe
DB_URL = os.getenv("DB_URL")
""")

        if (i + 1) % 100 == 0:
            print(f"  created {i + 1} files")

    return temp_dir


def run_benchmark(target_dir: str, iterations: int = 3):
    """run benchmark on target directory"""
    scanner = Scanner()
    files = get_files(target_dir)

    print(f"\nbenchmark: {len(files)} files")
    print("-" * 50)

    times = []
    findings_counts = []

    for i in range(iterations):
        start = time.time()

        findings = []
        for file_path in files:
            file_findings = scanner.scan_file(file_path, enable_entropy=True)
            findings.extend(file_findings)

        elapsed = time.time() - start
        times.append(elapsed)
        findings_counts.append(len(findings))

        print(f"iteration {i + 1}: {elapsed:.2f}s, {len(findings)} findings")

    avg_time = sum(times) / len(times)
    avg_findings = sum(findings_counts) / len(findings_counts)
    files_per_second = len(files) / avg_time

    print("-" * 50)
    print(f"average time: {avg_time:.2f}s")
    print(f"average findings: {avg_findings:.1f}")
    print(f"files/second: {files_per_second:.1f}")
    print(f"seconds/1000 files: {1000 / files_per_second:.2f}s")


def main():
    parser = argparse.ArgumentParser(description="benchmark gitvaultscanner")
    parser.add_argument(
        "--dir", help="directory to scan (creates temp if not provided)"
    )
    parser.add_argument(
        "--size", type=int, default=50, help="size in MB of temp test directory"
    )
    parser.add_argument(
        "--iterations", type=int, default=3, help="number of benchmark iterations"
    )

    args = parser.parse_args()

    if args.dir:
        target_dir = args.dir
        print(f"using existing directory: {target_dir}")
    else:
        print(f"creating {args.size}MB test directory...")
        target_dir = create_large_test_dir(args.size)
        print(f"created: {target_dir}")

    try:
        run_benchmark(target_dir, args.iterations)
    finally:
        # clean up temp dir if we created it
        if not args.dir and os.path.exists(target_dir):
            import shutil

            shutil.rmtree(target_dir)
            print(f"cleaned up: {target_dir}")


if __name__ == "__main__":
    main()
