import hashlib
import hmac


def evidence_matches(payload: bytes, claimed_digest: str) -> bool:
    """Bind the claim to the actual payload digest."""
    actual_digest = hashlib.sha256(payload).hexdigest()
    return hmac.compare_digest(actual_digest, claimed_digest)
