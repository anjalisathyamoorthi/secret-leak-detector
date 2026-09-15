"""Secret masking and fingerprint hashing utilities."""

import hashlib


def mask_secret(secret: str) -> str:
    """
    Mask a secret value showing only the first 4 and last 4 characters.
    Format example: sk_l****...**91ab
    """
    if not secret:
        return "********"
        
    length = len(secret)
    if length <= 8:
        if length <= 4:
            return "*" * length
        return secret[:2] + "*" * (length - 4) + secret[-2:]
        
    prefix = secret[:4]
    suffix = secret[-4:]
    return f"{prefix}****...**{suffix}"


def generate_fingerprint(secret: str) -> str:
    """
    Generate a one-way SHA-256 fingerprint hash for secret deduplication.
    Never stores or logs the plaintext secret value.
    """
    if not secret:
        return ""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()
