"""Evaluation script benchmarking Precision, Recall, F1 Score, and Scan Performance."""

import time
import os
import sys
from pathlib import Path
from typing import List, Dict, Any

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.detector import SecretDetector

# Expected ground truth findings in tests/fake_secrets
# Each entry: (file_name, expected_rule_id)
EXPECTED_FAKES = [
    ("api_keys.py", "stripe-key"),
    ("api_keys.py", "google-api-key"),
    ("api_keys.py", "github-token"),
    ("api_keys.py", "generic-api-key"),
    ("aws_credentials.py", "aws-access-key"),
    ("aws_credentials.py", "aws-secret-key"),
    ("db_config.py", "database-url"),
    ("db_config.py", "password-assignment"),
    ("tokens.py", "slack-token"),
    ("tokens.py", "jwt-token"),
    ("tokens.py", "oauth-token"),
    ("private_key.pem", "private-key-header"),
]


def run_evaluation():
    detector = SecretDetector()

    fake_dir = PROJECT_ROOT / "tests" / "fake_secrets"
    clean_dir = PROJECT_ROOT / "tests" / "clean_code"

    if not fake_dir.exists() or not clean_dir.exists():
        print("Error: Test directories not found.", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print(" SECRET LEAK DETECTOR ACCURACY & PERFORMANCE EVALUATION")
    print("=" * 60)

    # 1. Benchmark Fake Secrets (Known Positives)
    fake_files = [p for p in fake_dir.glob("*") if p.is_file()]
    fake_findings: List[Dict[str, Any]] = []

    start_time = time.perf_counter()
    total_fake_files = len(fake_files)
    for f in fake_files:
        findings = detector.scan_file(str(f))
        fake_findings.extend(findings)
    fake_scan_duration = time.perf_counter() - start_time

    # 2. Benchmark Clean Code (Known Negatives)
    clean_files = list(clean_dir.glob("*.py"))
    clean_findings: List[Dict[str, Any]] = []

    start_time = time.perf_counter()
    total_clean_files = len(clean_files)
    for f in clean_files:
        findings = detector.scan_file(str(f))
        clean_findings.extend(findings)
    clean_scan_duration = time.perf_counter() - start_time

    total_files = total_fake_files + total_clean_files
    total_duration = fake_scan_duration + clean_scan_duration
    avg_scan_time_ms = (total_duration / total_files * 1000.0) if total_files > 0 else 0.0

    # Calculate TP, FP, FN
    # True Positives: valid detections in fake_secrets matching rules
    # False Positives: detections in clean_code
    # False Negatives: expected rules missed in fake_secrets

    detected_rules = {(Path(f["file_path"]).name, f["rule_id"]) for f in fake_findings}

    tp = 0
    fn = 0
    for file_name, rule_id in EXPECTED_FAKES:
        if (file_name, rule_id) in detected_rules or any(f["rule_id"] == rule_id for f in fake_findings):
            tp += 1
        else:
            fn += 1

    fp = len(clean_findings)

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    print(f"Files Scanned:             {total_files} ({total_fake_files} positive, {total_clean_files} clean)")
    print(f"Total Detections:          {len(fake_findings) + len(clean_findings)}")
    print(f"True Positives (TP):       {tp}")
    print(f"False Positives (FP):      {fp}")
    print(f"False Negatives (FN):      {fn}")
    print("-" * 60)
    print(f"Precision:                 {precision * 100:.2f}%")
    print(f"Recall:                    {recall * 100:.2f}%")
    print(f"F1 Score:                  {f1_score * 100:.2f}%")
    print(f"Average Scan Time:         {avg_scan_time_ms:.2f} ms / file")
    print("=" * 60)

    # Return structured dict
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "avg_scan_time_ms": avg_scan_time_ms
    }


if __name__ == "__main__":
    run_evaluation()
