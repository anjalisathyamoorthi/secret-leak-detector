"""CSV report generator for Secret Leak Detector findings."""

import csv
import io
from typing import List, Dict, Any


def generate_csv_report(findings: List[Dict[str, Any]]) -> str:
    """
    Generate CSV report string from findings list.
    Guarantees full secret values are never included—only masked values and fingerprints.
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Write Header
    writer.writerow([
        "Finding ID",
        "Repository",
        "File Path",
        "Line Number",
        "Rule ID",
        "Severity",
        "Masked Value",
        "Fingerprint Hash",
        "Status",
        "Detected At",
        "Resolved At"
    ])

    # Write Rows
    for f in findings:
        writer.writerow([
            f.get("id", ""),
            f.get("repository", "default-repo"),
            f.get("file_path", ""),
            f.get("line_number", ""),
            f.get("rule_id", ""),
            f.get("severity", "").upper(),
            f.get("masked_value", ""),
            f.get("fingerprint", ""),
            f.get("status", "").upper(),
            f.get("created_at", ""),
            f.get("resolved_at", "")
        ])

    return output.getvalue()
