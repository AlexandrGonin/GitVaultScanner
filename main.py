"""
main.py - entry point for gitvaultscanner
handles command line arguments and orchestrates the scanning process
"""

import argparse
import os
import sys
import tempfile
from datetime import datetime
from typing import Optional

from config.settings import DEFAULT_CONFIG
from core.exceptions import ScannerException
from core.file_handler import get_files
from core.scanner import Scanner
from reporters.console_reporter import ConsoleReporter
from reporters.html_reporter import HtmlReporter
from reporters.json_reporter import JsonReporter
from reporters.sarif_reporter import SarifReporter
from utils.docker_utils import extract_image_layers, pull_docker_image
from utils.git_utils import clone_repository
from utils.progress_bar import ProgressBar
from utils.temp_cleaner import cleanup_temp_dirs

banner = """
    ╔════════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║   █▀▀ █ ▀█▀ █ █ ▄▀█ █ █ █   ▀█▀ █▀ █▀▀ ▄▀█ █▄ █ █▄ █ █▀▀ █▀█   ║
    ║   █▄█ █  █  ▀▄▀ █▀█ █▄█ █▄▄  █  ▄█ █▄▄ █▀█ █ ▀█ █ ▀█ ██▄ █▀▄   ║
    ║                                                                ║
    ║         GitHub & Local Directory Secrets Scanner               ║
    ║         Detects hardcoded credentials, API keys, tokens        ║
    ╚════════════════════════════════════════════════════════════════╝
"""

print(banner)


def parse_arguments():
    """parse command line arguments and return args object"""
    parser = argparse.ArgumentParser(
        description="gitvaultscanner - find hardcoded secrets in code and docker images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # target selection group
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("--repo", "-r", help="github repository url")
    target_group.add_argument("--dir", "-d", help="local directory path")
    target_group.add_argument(
        "--docker", "-i", help="docker image name (e.g. ubuntu:latest)"
    )

    # scan options
    parser.add_argument(
        "--output", "-o", help="save report to file (format determined by extension)"
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["console", "json", "sarif", "html"],
        default="console",
        help="output format",
    )
    parser.add_argument("--extensions", "-e", nargs="+", help="file extensions to scan")
    parser.add_argument(
        "--entropy", action="store_true", help="enable entropy-based detection"
    )
    parser.add_argument(
        "--validate", action="store_true", help="validate found secrets (aws, jwt)"
    )
    parser.add_argument(
        "--hibp", action="store_true", help="check passwords against have i been pwned"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true", help="keep temporary files after scan"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="verbose output")
    parser.add_argument("--config", help="path to custom config file")

    return parser.parse_args()


def setup_environment(args):
    """prepare directories and environment for scanning"""
    # create temp directory for this scan
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_base = os.path.join(tempfile.gettempdir(), f"gvs_{scan_id}")
    os.makedirs(temp_base, exist_ok=True)

    return temp_base


def main():
    """main execution function"""
    args = parse_arguments()
    temp_dir = setup_environment(args)
    start_time = datetime.now()

    try:
        # initialize scanner with configuration
        scanner = Scanner(config_path=args.config)

        # determine target type and prepare files
        target_path: Optional[str] = None
        target_name = "unknown"
        scan_type = "unknown"

        if args.repo:
            print(f"[*] cloning repository: {args.repo}")
            target_path = clone_repository(args.repo, temp_dir)
            target_name = args.repo.split("/")[-1].replace(".git", "")
            scan_type = "github"

        elif args.dir:
            print(f"[*] scanning local directory: {args.dir}")
            target_path = os.path.abspath(args.dir)
            target_name = os.path.basename(target_path)
            scan_type = "directory"

        elif args.docker:
            print(f"[*] pulling docker image: {args.docker}")
            image_path = pull_docker_image(args.docker, temp_dir)
            target_path = extract_image_layers(image_path, os.path.join(temp_dir, "fs"))

            if os.path.exists(target_path):
                files = os.listdir(target_path)
                # checking app dir exists
                app_path = os.path.join(target_path, "app")
                if os.path.exists(app_path) and os.path.isdir(app_path):
                    target_path = app_path
                    print(f"[*] scanning app directory: {app_path}")
                else:
                    # if there're no app start to find common locations
                    for possible_path in ["usr/src/app", "var/www", "home/app", "root"]:
                        test_path = os.path.join(target_path, possible_path)
                        if os.path.exists(test_path) and os.path.isdir(test_path):
                            target_path = test_path
                            break

            target_name = args.docker.replace("/", "_").replace(":", "_")
            scan_type = "docker"

        if target_path is None or not os.path.exists(target_path):
            print("[!] error: target path does not exist")
            sys.exit(1)

        # collect files for scanning
        print("[*] collecting files...")
        extensions = (
            args.extensions if args.extensions else DEFAULT_CONFIG["extensions"]
        )
        files = get_files(target_path, extensions)
        print(f"[*] found {len(files)} files to scan")

        # scan files
        print("[*] scanning for secrets...")
        progress = ProgressBar(len(files))
        all_findings = []

        for i, file_path in enumerate(files):
            progress.update(i + 1, f"scanning {os.path.basename(file_path)}")

            # run all enabled parsers on this file
            findings = scanner.scan_file(
                file_path,
                enable_entropy=args.entropy,
                validate=args.validate,
                hibp=args.hibp,
            )
            all_findings.extend(findings)

        progress.finish()

        # calculate scan time
        scan_time = (datetime.now() - start_time).total_seconds()

        # get HIBP statistics if used
        hibp_stats = None
        if args.hibp and hasattr(scanner, "hibp_checker") and scanner.hibp_checker:
            hibp_stats = scanner.hibp_checker.get_statistics()
            # reset for next scan (if any)
            scanner.hibp_checker.reset_statistics()

        # generate report
        print("[*] generating report...")

        if args.format == "console" or not args.output:
            ConsoleReporter.print_report(
                all_findings, target_name, scan_time, scan_type, hibp_stats
            )

        if args.output:
            output_format = args.format or os.path.splitext(args.output)[
                1
            ].lower().replace(".", "")

            if output_format == "json":
                JsonReporter.save_report(
                    all_findings,
                    target_name,
                    scan_time,
                    scan_type,
                    args.output,
                    hibp_stats,
                )
            elif output_format == "sarif":
                SarifReporter.save_report(
                    all_findings,
                    target_name,
                    scan_time,
                    scan_type,
                    args.output,
                    hibp_stats,
                )
            elif output_format == "html":
                HtmlReporter.save_report(
                    all_findings,
                    target_name,
                    scan_time,
                    scan_type,
                    args.output,
                    hibp_stats,
                )
            else:
                ConsoleReporter.save_text_report(
                    all_findings,
                    target_name,
                    scan_time,
                    scan_type,
                    args.output,
                    hibp_stats,
                )

            print(f"[*] report saved to: {args.output}")

        # determine exit code
        high_risk_count = len(
            [f for f in all_findings if f.get("severity") in ["high", "critical"]]
        )
        if high_risk_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except ScannerException as e:
        print(f"[!] scanner error: {str(e)}")
        sys.exit(2)
    except Exception as e:
        print(f"[!] unexpected error: {str(e)}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(3)
    finally:
        # cleanup temporary files
        if not args.no_cleanup and os.path.exists(temp_dir):
            cleanup_temp_dirs(temp_dir)
            print("[*] cleaned up temporary files")


if __name__ == "__main__":
    main()
