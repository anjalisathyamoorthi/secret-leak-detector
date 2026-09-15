"""Detection engine combining regex patterns and Shannon entropy analysis."""

import os
import re
import yaml
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

from scanner.entropy import calculate_entropy, find_high_entropy_strings, is_test_file, is_common_placeholder
from scanner.masker import mask_secret, generate_fingerprint

DEFAULT_RULES_PATH = Path(__file__).parent / "rules.yaml"


class SecretDetector:
    def __init__(self, rules_path: Optional[Path] = None):
        self.rules_path = rules_path or DEFAULT_RULES_PATH
        self.rules: List[Dict[str, Any]] = self._load_rules()

    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load regex rules from rules.yaml."""
        if not self.rules_path.exists():
            return []
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data.get("rules", [])
        except Exception:
            return []

    def scan_content(self, content: str, file_path: str = "") -> List[Dict[str, Any]]:
        """
        Scan string content for secrets using regex and entropy engines.
        Returns a list of finding dictionaries. Plaintext secrets are NEVER stored.
        """
        findings: List[Dict[str, Any]] = []
        matched_line_spans = set()  # (line_number, match_value)

        lines = content.splitlines()

        # 1. Regex Rule Matching
        for rule in self.rules:
            rule_id = rule.get("id", "generic-rule")
            rule_name = rule.get("name", rule_id)
            pattern_str = rule.get("pattern", "")
            severity = rule.get("severity", "high").lower()
            description = rule.get("description", "Potential secret detected")
            recommendation = rule.get("recommendation", "Remove the secret value")

            if not pattern_str:
                continue

            try:
                regex = re.compile(pattern_str)
            except re.error:
                continue

            for line_num, line in enumerate(lines, start=1):
                # Skip comment lines if full line comment
                trimmed = line.strip()
                if trimmed.startswith("#") or trimmed.startswith("//"):
                    # Check if it's explicitly labeled as fake/test credential
                    if "fake" in trimmed.lower() or "test" in trimmed.lower() or "do not use" in trimmed.lower():
                        pass  # Keep scanning, but severity adjustment will happen

                for match in regex.finditer(line):
                    matched_val = match.group(0)

                    # Extract extracted secret string inside assignment if present
                    secret_str = matched_val
                    if ":" in matched_val or "=" in matched_val:
                        parts = re.split(r'[:=]', matched_val, maxsplit=1)
                        if len(parts) > 1:
                            secret_str = parts[1].strip(" '\"\t\r\n")

                    if is_common_placeholder(secret_str):
                        continue

                    # Adjust severity if in test file or explicitly fake test credential
                    effective_severity = severity
                    if is_test_file(file_path) or "fake" in line.lower() or "test credential" in line.lower():
                        effective_severity = "low"

                    masked = mask_secret(secret_str)
                    fingerprint = generate_fingerprint(secret_str)

                    findings.append({
                        "rule_id": rule_id,
                        "rule_name": rule_name,
                        "file_path": file_path or "unknown",
                        "line_number": line_num,
                        "severity": effective_severity,
                        "masked_value": masked,
                        "fingerprint": fingerprint,
                        "description": description,
                        "recommendation": recommendation,
                    })

                    matched_line_spans.add((line_num, secret_str))

        # 2. Entropy Engine Scan (for suspicious strings not matched by regex)
        entropy_matches = find_high_entropy_strings(content, file_path=file_path)
        for line_num, val, entropy_score, var_name in entropy_matches:
            # Check if this line + value was already caught by regex
            if (line_num, val) in matched_line_spans:
                continue

            effective_severity = "medium"
            if is_test_file(file_path):
                effective_severity = "low"

            masked = mask_secret(val)
            fingerprint = generate_fingerprint(val)

            findings.append({
                "rule_id": "high-entropy-string",
                "rule_name": "High Entropy String",
                "file_path": file_path or "unknown",
                "line_number": line_num,
                "severity": effective_severity,
                "masked_value": masked,
                "fingerprint": fingerprint,
                "description": f"High Shannon entropy string detected (H={entropy_score:.2f})",
                "recommendation": "Review high entropy token to verify if it is an unformatted API key or hash",
            })

        return findings

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan a single file on disk."""
        path = Path(file_path)
        if not path.is_file():
            return []

        # Ignore binary files or common excluded extensions/dirs
        if self._should_skip_path(path):
            return []

        content = None
        for encoding in ["utf-8", "utf-8-sig", "utf-16", "latin-1"]:
            try:
                with open(path, "r", encoding=encoding) as f:
                    content = f.read()
                break
            except (UnicodeDecodeError, Exception):
                continue

        if content is None:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                return []

        return self.scan_content(content, file_path=str(path))

    def scan_directory(self, dir_path: str) -> Dict[str, Any]:
        """Recursively scan a directory for secrets."""
        root_path = Path(dir_path)
        all_findings = []
        files_scanned = 0

        for path in root_path.rglob("*"):
            if path.is_file() and not self._should_skip_path(path):
                files_scanned += 1
                file_findings = self.scan_file(str(path))
                all_findings.extend(file_findings)

        return {
            "files_scanned": files_scanned,
            "findings": all_findings,
            "findings_count": len(all_findings),
        }

    def _should_skip_path(self, path: Path) -> bool:
        """Skip binary files, git internal files, or virtual environment directories."""
        skip_dirs = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache", ".idea", ".vscode"}
        skip_exts = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar", ".gz", ".exe", ".dll", ".so", ".db", ".sqlite"}

        for part in path.parts:
            if part in skip_dirs:
                return True

        if path.suffix.lower() in skip_exts:
            return True

        return False
