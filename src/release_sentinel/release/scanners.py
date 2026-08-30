from __future__ import annotations

import hashlib
import re
from pathlib import Path

from release_sentinel.domain.evidence import Evidence, EvidenceAuthority, EvidenceKind, Finding, Severity

_SECRET_PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic_secret": re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"][^'\"]{12,}['\"]"),
}
_SKIP = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}


def scan_platform_rules(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    root = root.resolve()
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or any(part in _SKIP for part in path.parts):
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        relative = path.relative_to(root)
        for line_no, line in enumerate(text.splitlines(), 1):
            for rule, pattern in _SECRET_PATTERNS.items():
                if not pattern.search(line):
                    continue
                token = hashlib.sha256(f"{relative}:{line_no}:{rule}".encode()).hexdigest()[:12]
                evidence = Evidence(
                    evidence_id=f"ev-static-{token}",
                    kind=EvidenceKind.STATIC_RULE,
                    authority=EvidenceAuthority.PLATFORM,
                    source="platform.secret_scan",
                    summary=f"Credential-like material matched {rule} in {relative}:{line_no}; value redacted.",
                    reproducible=True,
                    blocking_eligible=True,
                    details={"file": str(relative), "line": line_no, "rule": rule, "redacted": True},
                )
                findings.append(Finding(
                    finding_id=f"SEC-{token[:8]}",
                    title="Credential-like material in repository",
                    severity=Severity.HIGH,
                    source="platform.secret_scan",
                    claim="Platform policy forbids credential-like material in release source.",
                    evidence=[evidence],
                ))
    return findings
