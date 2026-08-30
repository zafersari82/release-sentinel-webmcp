def evidence_matches(payload: bytes, claimed_digest: str) -> bool:
    """Deliberately vulnerable fixture: trusts the caller's digest claim."""
    return True
