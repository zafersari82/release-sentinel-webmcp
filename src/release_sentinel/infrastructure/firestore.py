from __future__ import annotations

from copy import deepcopy
from typing import Any

from release_sentinel.agents.memory import safe_report_summary
from release_sentinel.domain.release import ReleaseReport
from release_sentinel.policy.model import PolicyError, ReleasePolicy, build_policy


class FirestorePolicyStore:
    """Immutable organization policy revisions in a dedicated named database."""

    def __init__(self, project_id: str, database: str) -> None:
        from google.cloud import firestore
        self._client = firestore.Client(project=project_id, database=database)
        self._collection = self._client.collection("release_policies")

    @staticmethod
    def _doc_id(policy_id: str, revision: int) -> str:
        return f"{policy_id}--r{revision}"

    def create(self, policy: ReleasePolicy) -> None:
        payload = policy.canonical_payload()
        document = {"policy": payload, "sha256": policy.sha256}
        try:
            self._collection.document(self._doc_id(policy.policy_id, policy.revision)).create(document)
        except Exception as exc:
            # Firestore AlreadyExists is intentionally surfaced as immutable-revision failure.
            if exc.__class__.__name__ in {"AlreadyExists", "Conflict"}:
                raise PolicyError("policy revision already exists and is immutable") from exc
            raise

    def get(self, policy_id: str, revision: int) -> ReleasePolicy:
        snap = self._collection.document(self._doc_id(policy_id, revision)).get()
        if not snap.exists:
            raise PolicyError("policy revision not found")
        raw: dict[str, Any] = deepcopy(snap.to_dict() or {})
        policy = build_policy(raw.get("policy"))
        if raw.get("sha256") != policy.sha256:
            raise PolicyError("stored policy hash mismatch")
        return policy


class FirestoreReportLedger:
    """Append-only release reports in the ledger database."""

    def __init__(self, project_id: str, database: str) -> None:
        from google.cloud import firestore
        self._client = firestore.Client(project=project_id, database=database)
        self._collection = self._client.collection("release_reports")

    def append(self, report: ReleaseReport, *, provenance: dict[str, Any] | None = None) -> str:
        return self.append_payload(report.report_id, report.to_dict(), provenance=provenance)

    def append_payload(self, report_id: str, report: dict[str, Any], *, provenance: dict[str, Any] | None = None) -> str:
        report_copy = deepcopy(report)
        release_id = str(report_copy.get("release_id") or "")
        created_at = str(report_copy.get("created_at") or "")
        document = {
            "report": report_copy,
            "provenance": deepcopy(provenance),
            # One-field sortable history key keeps recent_for_release bounded without
            # requiring a new storage subsystem or a compound Firestore index.
            "history_key": f"{release_id}:{created_at}:{report_id}" if release_id else "",
        }
        self._collection.document(report_id).create(document)
        return report_id

    def recent_for_release(self, release_id: str, limit: int = 5) -> list[dict[str, Any]]:
        if not release_id or limit < 1 or limit > 20:
            raise ValueError("release history query is out of bounds")
        from google.cloud import firestore
        from google.cloud.firestore_v1.base_query import FieldFilter

        prefix = f"{release_id}:"
        query = (
            self._collection
            .where(filter=FieldFilter("history_key", ">=", prefix))
            .where(filter=FieldFilter("history_key", "<=", prefix + "\uf8ff"))
            .order_by("history_key", direction=firestore.Query.DESCENDING)
            .limit(limit)
        )
        return [safe_report_summary(snapshot.to_dict() or {}) for snapshot in query.stream()]
