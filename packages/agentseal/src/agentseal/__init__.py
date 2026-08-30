"""agentseal — prove the model in your pipeline couldn't touch the output.

A signature proves *who* signed. It does not prove that what was signed is
true. If an LLM stage sits upstream of your signer holding a reference to the
evidence, it can produce a cryptographically valid attestation over tampered
data — every individual claim true, the aggregate a lie.

agentseal gives you two things:

    seal(data)                  a deeply immutable projection to hand untrusted
                                stages instead of your live objects

    assert_no_influence(pipe)   a differential test that runs your pipeline with
                                a hostile stage substituted in and asserts the
                                artifact is byte-identical

The second one is the point. It does not require you to enumerate every path
from the model to the outcome and prove each is zero — the assumption that
tends to be wrong. It asserts the artifact does not move, whatever the model
did.
"""

from __future__ import annotations

from .check import (
    InfluenceReport,
    VariantResult,
    assert_no_influence,
    check_no_influence,
)
from .certificate import CounterfactualCertificate, build_certificate, verify_certificate
from .hostile import Baseline, HostileVariant, default_variants
from .seal import SealBroken, canonical_bytes, fingerprint, seal
from .stage import sealed_stage

__version__ = "0.2.0"

__all__ = [
    "seal",
    "sealed_stage",
    "fingerprint",
    "canonical_bytes",
    "SealBroken",
    "assert_no_influence",
    "check_no_influence",
    "InfluenceReport",
    "VariantResult",
    "CounterfactualCertificate",
    "build_certificate",
    "verify_certificate",
    "HostileVariant",
    "default_variants",
    "Baseline",
    "__version__",
]
