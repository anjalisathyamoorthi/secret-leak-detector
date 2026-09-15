"""Shannon entropy calculation and high-entropy string extraction."""

import math
import re
from typing import List, Tuple, Dict, Any

COMMON_PLACEHOLDERS = {
    "xxxxxxxx", "your_key_here", "changeme", "example", "00000000",
    "abcdef1234567890", "abcdefghijklmnopqrstuvwxyz", "12345678901234567890",
    "xxxx-xxxx-xxxx-xxxx", "your_api_key_goes_here", "dummy_secret_value",
    "fake_key_for_testing_only"
}

TEST_PATH_KEYWORDS = ["test", "__tests__", "fixtures", "tests", "mock", "spec"]
CONTEXT_KEYWORDS = ["password", "secret", "token", "key", "credential", "auth", "pwd", "api"]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    
    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
        
    entropy = 0.0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
        
    return entropy


def is_test_file(file_path: str) -> bool:
    """Check if the given file path belongs to a test/fixture directory or file."""
    normalized_path = file_path.lower().replace("\\", "/")
    parts = normalized_path.split("/")
    for part in parts:
        if any(keyword in part for keyword in TEST_PATH_KEYWORDS):
            return True
    return False


def is_common_placeholder(val: str) -> bool:
    """Check if a string matches common placeholder patterns."""
    val_lower = val.lower().strip()
    if val_lower in COMMON_PLACEHOLDERS:
        return True
    
    # Check repeated characters or simple sequences
    if len(set(val_lower)) <= 3:
        return True
        
    if "your_" in val_lower or "_here" in val_lower or "fake_" in val_lower or "dummy" in val_lower:
        return True
        
    return False


def find_high_entropy_strings(
    content: str,
    file_path: str = "",
    min_length: int = 20,
    max_length: int = 64,
    min_entropy: float = 4.3
) -> List[Tuple[int, str, float, str]]:
    """
    Extract high-entropy strings from quotes/assignments.
    Returns list of tuples: (line_number, string_val, entropy_score, context_var)
    """
    results: List[Tuple[int, str, float, str]] = []
    
    # Skip test files if desired by caller or flag
    # Regex to extract string literals in single/double quotes or backticks
    string_pattern = re.compile(
        r'(?P<var>[A-Za-z0-9_]+)?\s*[:=]?\s*[\'"`](?P<val>[^\'"\r\n]{' + str(min_length) + r',' + str(max_length) + r'})[\'"`]'
    )

    lines = content.splitlines()
    for line_idx, line in enumerate(lines, start=1):
        # Skip comment lines if simple
        trimmed = line.strip()
        if trimmed.startswith("#") or trimmed.startswith("//") or trimmed.startswith("/*"):
            continue
            
        for match in string_pattern.finditer(line):
            val = match.group('val')
            var = match.group('var') or ''
            
            if not (min_length <= len(val) <= max_length):
                continue
                
            if is_common_placeholder(val):
                continue
                
            entropy = calculate_entropy(val)
            if entropy > min_entropy:
                # Check context signal
                var_lower = var.lower()
                line_lower = line.lower()
                has_context = any(kw in var_lower or kw in line_lower for kw in CONTEXT_KEYWORDS)
                
                # If in test file and no strong context, skip
                if is_test_file(file_path) and not has_context:
                    continue
                    
                results.append((line_idx, val, entropy, var))
                
    return results
