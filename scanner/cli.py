"""CLI interface for Secret Leak Detector."""

import argparse
import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.detector import SecretDetector


def ensure_git_in_path():
    """Ensure git binary is accessible in environment PATH on Windows if needed."""
    if shutil.which("git") is None:
        possible_paths = [
            r"C:\Users\Anjal\AppData\Local\GitHubDesktop\app-3.5.10\resources\app\git\cmd",
            r"C:\Program Files\Git\cmd",
            r"C:\Program Files (x86)\Git\cmd",
        ]
        for p in possible_paths:
            if os.path.isdir(p):
                os.environ["PATH"] += os.pathsep + p
                break


def format_finding(finding: Dict[str, Any]) -> str:
    """Format finding output to match exact required style."""
    severity = finding["severity"].upper()
    rule_id = finding["rule_id"]
    file_path = finding["file_path"]
    line_number = finding["line_number"]
    masked_val = finding["masked_value"]
    recommendation = finding.get("recommendation", "Remove the value and rotate the credential")
    rule_name = finding.get("rule_name", rule_id)

    return (
        f"[{severity}] {rule_name} detected\n"
        f"File: {file_path}\n"
        f"Line: {line_number}\n"
        f"Rule: {rule_id}\n"
        f"Masked value: {masked_val}\n"
        f"Action: {recommendation}"
    )


def scan_staged_files(detector: SecretDetector) -> List[Dict[str, Any]]:
    """Scan only staged Git files (git diff --cached --name-only)."""
    ensure_git_in_path()
    try:
        res = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True
        )
        staged_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
    except Exception as e:
        print(f"Error checking staged git files: {e}", file=sys.stderr)
        return []

    all_findings = []
    for file_path in staged_files:
        if os.path.isfile(file_path):
            findings = detector.scan_file(file_path)
            all_findings.extend(findings)
    return all_findings


def scan_git_history(detector: SecretDetector) -> List[Dict[str, Any]]:
    """Scan Git log/history (git log -p)."""
    ensure_git_in_path()
    try:
        res = subprocess.run(
            ["git", "log", "-p", "-n", "50"],
            capture_output=True,
            text=True,
            check=True
        )
        history_text = res.stdout
        return detector.scan_content(history_text, file_path="git-history")
    except Exception as e:
        print(f"Error scanning git history: {e}", file=sys.stderr)
        return []


def install_pre_commit_hook():
    """Install the custom pre-commit hook into .git/hooks/pre-commit."""
    ensure_git_in_path()
    git_dir = Path(".git")
    if not git_dir.exists() or not git_dir.is_dir():
        print("Error: Not a git repository. Run 'git init' first.", file=sys.stderr)
        sys.exit(1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_file = hooks_dir / "pre-commit"

    # Python script pre-commit runner hook
    hook_content = """#!/usr/bin/env python
import sys
import os
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from hooks.pre_commit_hook import main

if __name__ == "__main__":
    sys.exit(main())
"""

    try:
        with open(hook_file, "w", encoding="utf-8") as f:
            f.write(hook_content)

        # Make executable on Unix systems
        if os.name != "nt":
            mode = os.stat(hook_file).st_mode
            os.chmod(hook_file, mode | 0o755)

        print(f"Successfully installed Secret Leak Detector pre-commit hook to {hook_file}")
    except Exception as e:
        print(f"Failed to install pre-commit hook: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(prog="secret-detector", description="Secret Leak Detector CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # init command
    subparsers.add_parser("init", help="Install the Git pre-commit hook")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan files, directories, staged changes, or Git history")
    scan_parser.add_argument("target", nargs="?", default=".", help="File or directory path to scan")
    scan_parser.add_argument("--staged", action="store_true", help="Scan staged Git files only")
    scan_parser.add_argument("--history", action="store_true", help="Scan Git log/history")
    scan_parser.add_argument("--json", action="store_true", help="Output findings as JSON")

    args = parser.parse_args()

    detector = SecretDetector()

    if args.command == "init":
        install_pre_commit_hook()
        sys.exit(0)

    elif args.command == "scan" or args.command is None:
        findings = []

        if getattr(args, "staged", False):
            findings = scan_staged_files(detector)
        elif getattr(args, "history", False):
            findings = scan_git_history(detector)
        else:
            target_path = getattr(args, "target", ".")
            if os.path.isfile(target_path):
                findings = detector.scan_file(target_path)
            elif os.path.isdir(target_path):
                result = detector.scan_directory(target_path)
                findings = result["findings"]
            else:
                print(f"Error: Path '{target_path}' does not exist.", file=sys.stderr)
                sys.exit(1)

        # Output findings
        has_high_or_critical = False
        if findings:
            for finding in findings:
                print(format_finding(finding))
                print("-" * 50)
                if finding["severity"].lower() in ["high", "critical"]:
                    has_high_or_critical = True
        else:
            print("No secrets detected. Code looks clean!")

        if has_high_or_critical:
            sys.exit(1)
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
