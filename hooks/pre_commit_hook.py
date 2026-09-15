"""Git pre-commit hook implementation. Blocks commits with HIGH/CRITICAL secret findings."""

import os
import sys
import shutil
import datetime
import subprocess
import requests
from pathlib import Path
from typing import List, Dict, Any, Optional

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.detector import SecretDetector
from scanner.cli import format_finding, ensure_git_in_path

BACKEND_URL = os.getenv("SECRET_DETECTOR_API_URL", "http://127.0.0.1:8000/api")


def get_git_user_email() -> str:
    """Retrieve git user email or username for auditing."""
    ensure_git_in_path()
    try:
        res = subprocess.run(["git", "config", "user.email"], capture_output=True, text=True)
        email = res.stdout.strip()
        if email:
            return email
        res = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True)
        name = res.stdout.strip()
        if name:
            return name
    except Exception:
        pass
    return os.getenv("USERNAME") or os.getenv("USER") or "unknown_user"


def get_repo_name() -> str:
    """Retrieve git repository name or directory name."""
    ensure_git_in_path()
    try:
        res = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
        top_level = res.stdout.strip()
        if top_level:
            return Path(top_level).name
    except Exception:
        pass
    return Path.cwd().name


def post_scan_results(repo_name: str, files_scanned: int, findings: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Send scan results to backend API asynchronously/gracefully."""
    url = f"{BACKEND_URL}/scans"
    payload = {
        "repository_name": repo_name,
        "scan_type": "pre-commit",
        "files_scanned": files_scanned,
        "findings": findings,
    }
    try:
        resp = requests.post(url, json=payload, timeout=2.0)
        if resp.status_code in (200, 201):
            return resp.json()
    except Exception:
        # Backend might be offline; allow hook execution without crashing
        pass
    return None


def post_bypass_log(user_email: str, reason: str, repo_name: str):
    """Log commit bypass event to backend API."""
    url = f"{BACKEND_URL}/bypasses"
    payload = {
        "user_email": user_email,
        "repository_name": repo_name,
        "reason": reason,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }
    try:
        requests.post(url, json=payload, timeout=2.0)
    except Exception:
        pass


def main() -> int:
    """
    Pre-commit hook main execution flow.
    Returns 0 to allow commit, 1 to block commit.
    """
    ensure_git_in_path()
    
    # 1. Get staged files
    try:
        res = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True,
            check=True
        )
        staged_files = [f.strip() for f in res.stdout.splitlines() if f.strip()]
    except Exception as e:
        print(f"Secret Leak Detector Hook Error: Failed to list staged files ({e})", file=sys.stderr)
        return 0  # Fail open if git command fails

    if not staged_files:
        return 0

    detector = SecretDetector()
    all_findings = []
    
    for file_path in staged_files:
        if os.path.isfile(file_path):
            try:
                findings = detector.scan_file(file_path)
                # If staged file is NOT in a test folder, ensure rule severity is preserved
                if "tests/fake_secrets" not in file_path.replace("\\", "/"):
                    for finding in findings:
                        rule_id = finding["rule_id"]
                        for r in detector.rules:
                            if r["id"] == rule_id:
                                finding["severity"] = r.get("severity", "high")
                all_findings.extend(findings)
            except Exception:
                pass

    repo_name = get_repo_name()
    user_email = get_git_user_email()

    # 2. Post scan metrics to API
    post_scan_results(repo_name, len(staged_files), all_findings)

    # 3. Evaluate blocking criteria
    high_critical_findings = [
        f for f in all_findings if f["severity"].lower() in ["high", "critical"]
    ]

    if high_critical_findings:
        print("\n" + "=" * 60)
        print(" [SECURITY ALERT] SECRET LEAK DETECTED - COMMIT BLOCKED")
        print("=" * 60)
        for finding in high_critical_findings:
            print(format_finding(finding))
            print("-" * 50)
        print("\nCommit aborted! Please remove the leaked secrets before committing.")
        print("If this is a false positive and emergency bypass is required, use:")
        print("  git commit --no-verify")
        print("=" * 60 + "\n")
        return 1

    if all_findings:
        print("\n[Secret Detector Warning] Low/Medium findings detected:")
        for finding in all_findings:
            print(f"  - [{finding['severity'].upper()}] {finding['rule_id']} in {finding['file_path']}:{finding['line_number']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
