import argparse
import sys
import os
from pathlib import Path
from typing import List, Optional

from secrettrack.scanner.filesystem import FileSystemScanner
from secrettrack.report.human import HumanReport
from secrettrack.report.json import JSONReport


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Secrets Hunter - Detect exposed secrets in your codebase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scan /path/to/project
  %(prog)s scan . --exclude "node_modules,*.log"
  %(prog)s scan . --json --severity critical,high
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Scan command
    scan_parser = subparsers.add_parser(
        "scan", help="Scan a directory for exposed secrets"
    )
    scan_parser.add_argument(
        "path",
        type=str,
        help="Path to scan (directory or file)",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output results in JSON format",
    )
    scan_parser.add_argument(
        "--severity",
        type=str,
        default="low,medium,high,critical",
        help="Comma-separated list of severities to include (low,medium,high,critical)",
    )
    scan_parser.add_argument(
        "--exclude",
        type=str,
        default="node_modules,.git,__pycache__,*.pyc,*.pyo,*.pyd,.DS_Store",
        help="Comma-separated list of patterns to exclude",
    )
    scan_parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Output file (default: stdout)",
    )

    args = parser.parse_args()

    if args.command == "scan":
        run_scan(args)
    else:
        parser.print_help()
        sys.exit(1)


def run_scan(args):
    """Run the scan command."""
    # Convert path to absolute
    scan_path = Path(args.path).absolute()
    
    if not scan_path.exists():
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)

    # Parse severity filter
    severity_filter = [s.strip().lower() for s in args.severity.split(",")]
    
    # Parse exclude patterns
    exclude_patterns = [p.strip() for p in args.exclude.split(",")]
    
    # Initialize scanner
    scanner = FileSystemScanner(exclude_patterns=exclude_patterns)
    
    print(f"🔍 Scanning {scan_path}...")
    results = scanner.scan(scan_path)
    
    # Filter by severity
    filtered_results = [
        r for r in results 
        if r.get("severity", "low").lower() in severity_filter
    ]
    
    # Generate report
    if args.json:
        report = JSONReport(filtered_results).generate()
    else:
        report = HumanReport(filtered_results).generate()
    
    # Output results
    if args.output:
        with open(args.output, "w") as f:
            f.write(report)
        print(f"📄 Report saved to {args.output}")
    else:
        print(report)
    
    # Exit with appropriate code
    critical_findings = any(r.get("severity") == "critical" for r in filtered_results)
    if critical_findings:
        sys.exit(2)
    elif filtered_results:
        sys.exit(1)
    else:
        print("✅ No secrets found!")
        sys.exit(0)


if __name__ == "__main__":
    main()