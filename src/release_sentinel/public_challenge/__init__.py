"""Public adversarial challenge primitives.

The public challenge plane is intentionally outside the release-authority trust
kernel. It may be compromised without gaining signing or verdict authority.
"""

from .protocol import (
    ATTACK_SCHEMA,
    RECEIPT_SCHEMA,
    SNAPSHOT_SCHEMA,
    AttackProtocolError,
    PublicChallengeReceipt,
    build_snapshot,
    validate_advisory_payload,
)
from .evaluator import evaluate_public_payload

__all__ = [
    "ATTACK_SCHEMA",
    "RECEIPT_SCHEMA",
    "SNAPSHOT_SCHEMA",
    "AttackProtocolError",
    "PublicChallengeReceipt",
    "build_snapshot",
    "validate_advisory_payload",
    "evaluate_public_payload",
]
