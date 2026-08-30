from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Callable

from release_sentinel.coverage.canonical import sha256_json
from release_sentinel.coverage.models import OracleVerdict
from release_sentinel.coverage.oracle import (
    OracleEvaluation,
    OracleFailure,
    OracleQualificationResult,
)


@dataclass(frozen=True)
class PathOracleVector:
    vector_id: str
    base_dir: Any
    requested_path: Any
    resolved_target: Any
    expected: bool
    category: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PathTraversalOracle:
    """Reference specification for POSIX-style path containment.

    The third argument is the filesystem-resolved target. This lets the oracle
    express symlink escapes without granting benchmark candidates filesystem
    access. Candidates must preserve both lexical and resolved containment.
    """

    REVISION = "path-traversal-oracle-v1"

    def __init__(self) -> None:
        base = "/srv/assets"
        self.vectors: tuple[PathOracleVector, ...] = (
            PathOracleVector("safe-basic", base, "images/logo.png", f"{base}/images/logo.png", True, "contained"),
            PathOracleVector("safe-dot", base, "./images/logo.png", f"{base}/images/logo.png", True, "contained"),
            PathOracleVector("safe-collapse", base, "images/../css/app.css", f"{base}/css/app.css", True, "contained"),
            PathOracleVector("safe-space", base, "space name.txt", f"{base}/space name.txt", True, "contained"),
            PathOracleVector("safe-unicode", base, "müşteri/ç.png", f"{base}/müşteri/ç.png", True, "contained"),
            PathOracleVector("safe-double-slash", base, "a//b.txt", f"{base}/a/b.txt", True, "contained"),
            PathOracleVector("safe-inner-dot", base, "a/./b.txt", f"{base}/a/b.txt", True, "contained"),
            PathOracleVector("safe-encoded-dot", base, "a/%2e/b.txt", f"{base}/a/b.txt", True, "encoded"),
            PathOracleVector("safe-encoded-char", base, "%66ile.txt", f"{base}/file.txt", True, "encoded"),
            PathOracleVector("dotdot-one", base, "../secret.txt", "/srv/secret.txt", False, "dotdot"),
            PathOracleVector("dotdot-two", base, "../../etc/passwd", "/etc/passwd", False, "dotdot"),
            PathOracleVector("encoded-dotdot", base, "%2e%2e/secret.txt", "/srv/secret.txt", False, "encoded"),
            PathOracleVector("encoded-double", base, "%252e%252e%252fsecret.txt", "/srv/secret.txt", False, "encoded"),
            PathOracleVector("backslash", base, "..\\secret.txt", "/srv/secret.txt", False, "backslash"),
            PathOracleVector("encoded-backslash", base, "%2e%2e%5csecret.txt", "/srv/secret.txt", False, "backslash"),
            PathOracleVector("absolute", base, "/etc/passwd", "/etc/passwd", False, "absolute"),
            PathOracleVector("encoded-absolute", base, "%2fetc%2fpasswd", "/etc/passwd", False, "absolute"),
            PathOracleVector("absolute-inside", base, "/srv/assets/file.txt", f"{base}/file.txt", False, "absolute"),
            PathOracleVector("symlink", base, "link/passwd", "/etc/passwd", False, "symlink_escape"),
            PathOracleVector("nested-symlink", base, "safe/link/key", "/var/keys/key", False, "symlink_escape"),
            PathOracleVector("prefix-collision", base, "file.txt", "/srv/assets_evil/file.txt", False, "prefix_collision"),
            PathOracleVector("sibling-collision", base, "file.txt", "/srv/asset/file.txt", False, "prefix_collision"),
            PathOracleVector("empty-request", base, "", base, False, "malformed"),
            PathOracleVector("nul-byte", base, "safe\x00/evil", f"{base}/safe", False, "malformed"),
            PathOracleVector("relative-base", "srv/assets", "file.txt", "srv/assets/file.txt", False, "malformed"),
            PathOracleVector("relative-resolved", base, "file.txt", "srv/assets/file.txt", False, "malformed"),
        )

    @property
    def qualification_manifest(self) -> dict[str, Any]:
        return {
            "schema": "release-sentinel.oracle-qualification.v1",
            "oracle_revision": self.REVISION,
            "vectors": [item.to_dict() for item in self.vectors],
            "mutants": [
                "allow_all",
                "lexical_only",
                "naive_prefix",
                "allow_absolute_inside",
                "allow_empty",
            ],
        }

    @property
    def qualification_manifest_sha256(self) -> str:
        return sha256_json(self.qualification_manifest)

    def evaluate_callable(self, can_open_path: Callable[..., Any]) -> OracleEvaluation:
        failures: list[OracleFailure] = []
        for vector in self.vectors:
            actual: bool | None
            error: str | None = None
            try:
                actual = bool(can_open_path(vector.base_dir, vector.requested_path, vector.resolved_target))
            except Exception as exc:
                actual = None
                error = f"{type(exc).__name__}: {exc}"
            if actual is not vector.expected:
                failures.append(
                    OracleFailure(
                        vector_id=vector.vector_id,
                        category=vector.category,
                        expected=vector.expected,
                        actual=actual,
                        error=error,
                    )
                )
        return OracleEvaluation(
            verdict=OracleVerdict.SAFE if not failures else OracleVerdict.UNSAFE,
            total_vectors=len(self.vectors),
            passed_vectors=len(self.vectors) - len(failures),
            failed_vectors=tuple(failures),
        )

    @staticmethod
    def _lexical_only(base_dir: Any, requested_path: Any, _resolved_target: Any) -> bool:
        import posixpath
        from urllib.parse import unquote

        if not isinstance(base_dir, str) or not isinstance(requested_path, str):
            return False
        if not base_dir.startswith("/") or not requested_path or "\x00" in requested_path:
            return False
        decoded = requested_path
        for _ in range(3):
            next_value = unquote(decoded)
            if next_value == decoded:
                break
            decoded = next_value
        decoded = decoded.replace("\\", "/")
        if decoded.startswith("/"):
            return False
        base = posixpath.normpath(base_dir)
        lexical = posixpath.normpath(posixpath.join(base, decoded))
        try:
            return posixpath.commonpath((base, lexical)) == base
        except ValueError:
            return False

    def _mutation_results(self) -> tuple[int, int]:
        import posixpath

        mutants: dict[str, Callable[..., bool]] = {
            "allow_all": lambda _base, _request, _resolved: True,
            "lexical_only": self._lexical_only,
            "naive_prefix": lambda base, _request, resolved: isinstance(base, str) and isinstance(resolved, str) and resolved.startswith(base),
            "allow_absolute_inside": lambda base, _request, resolved: isinstance(base, str) and isinstance(resolved, str) and posixpath.normpath(resolved).startswith(posixpath.normpath(base) + "/"),
            "allow_empty": lambda base, request, resolved: request == "" or self._lexical_only(base, request, resolved),
        }
        killed = 0
        for mutant in mutants.values():
            if self.evaluate_callable(mutant).verdict is OracleVerdict.UNSAFE:
                killed += 1
        return killed, len(mutants) - killed

    def qualify(
        self,
        *,
        fixed_callable: Callable[..., Any],
        vulnerable_callable: Callable[..., Any],
    ) -> OracleQualificationResult:
        fixed = self.evaluate_callable(fixed_callable)
        vulnerable = self.evaluate_callable(vulnerable_callable)
        killed, survived = self._mutation_results()
        passed = (
            fixed.verdict is OracleVerdict.SAFE
            and vulnerable.verdict is OracleVerdict.UNSAFE
            and survived == 0
        )
        selftest_payload = {
            "manifest_sha256": self.qualification_manifest_sha256,
            "fixed": fixed.to_dict(),
            "vulnerable": vulnerable.to_dict(),
            "mutation_killed": killed,
            "mutation_survived": survived,
            "passed": passed,
        }
        return OracleQualificationResult(
            passed=passed,
            fixed_verdict=fixed.verdict,
            vulnerable_verdict=vulnerable.verdict,
            mutation_killed=killed,
            mutation_survived=survived,
            mutation_total=killed + survived,
            manifest_sha256=self.qualification_manifest_sha256,
            selftest_sha256=sha256_json(selftest_payload),
        )
