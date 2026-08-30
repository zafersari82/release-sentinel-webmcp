from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Any
from urllib.parse import urlparse

from release_sentinel.parity.model import Observation, ParityScenario


class TargetMode(str, Enum):
    PRODUCTION_READONLY = "PRODUCTION_READONLY"
    SANDBOX = "SANDBOX"


@dataclass(frozen=True)
class TargetProfile:
    profile_id: str
    base_url: str
    mode: TargetMode


class ProbeError(RuntimeError):
    pass


def validate_target(profile: TargetProfile, *, allow_local: bool = False) -> None:
    parsed = urlparse(profile.base_url)
    if parsed.scheme not in ({"http", "https"} if allow_local else {"https"}):
        raise ProbeError("target scheme is not allowed")
    host = parsed.hostname
    if not host:
        raise ProbeError("target host is missing")
    if host in {"metadata.google.internal", "169.254.169.254"}:
        raise ProbeError("metadata target is forbidden")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip and not allow_local and (ip.is_private or ip.is_loopback or ip.is_link_local):
        raise ProbeError("private/local target is forbidden")


Transport = Callable[[TargetProfile, ParityScenario], tuple[int, Any]]


def run_dual_probe(
    scenarios: list[ParityScenario],
    legacy_profile: TargetProfile,
    candidate_profile: TargetProfile,
    transport: Transport,
    *,
    allow_local: bool = False,
) -> tuple[dict[str, Observation], dict[str, Observation]]:
    validate_target(legacy_profile, allow_local=allow_local)
    validate_target(candidate_profile, allow_local=allow_local)
    if legacy_profile.profile_id == candidate_profile.profile_id:
        raise ProbeError("legacy and candidate profiles must differ")
    legacy: dict[str, Observation] = {}
    candidate: dict[str, Observation] = {}
    for scenario in scenarios:
        method = scenario.method.upper()
        if method not in {"GET", "HEAD", "OPTIONS"} and not (
            legacy_profile.mode == TargetMode.SANDBOX and candidate_profile.mode == TargetMode.SANDBOX
        ):
            raise ProbeError("state-changing parity probes require two sandbox targets")
        try:
            ls, lp = transport(legacy_profile, scenario)
            cs, cp = transport(candidate_profile, scenario)
        except Exception as exc:
            raise ProbeError(f"transport failed for {scenario.scenario_id}: {type(exc).__name__}") from exc
        legacy[scenario.scenario_id] = Observation.from_payload(ls, lp)
        candidate[scenario.scenario_id] = Observation.from_payload(cs, cp)
    return legacy, candidate
