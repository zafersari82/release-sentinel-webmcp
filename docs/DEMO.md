# 60-second jury demo — Release Sentinel

1. Open **Enterprise Agent Control Plane / Judge View**. Point out **4 ADVISORY + 1 DETERMINISTIC** agents from the live registry.
2. Show the distributed trace path: **Python → ADK advisory fleet → A2A → Go Gatekeeper**. The same W3C trace context crosses the HTTP boundary.
3. Show **TRUST BOUNDARY: agent_influence = 0**. Advisory opinions are visible but never authoritative.
4. Show signed machine evidence and its authority. In a real cloud proof this must be KMS-backed and verified; do not claim VERIFIED from a synthetic/local-only state.
5. Run the six predefined resilience scenarios. A blocking signed-evidence release remains **NO_GO**, even when all advisory opinions say GO or telemetry/registry/memory are unavailable.
6. Show the private A2A Agent Card: Google OIDC / Cloud Run IAM, exact service audience, no unauthenticated scheme.
7. For the live-cloud proof, run the **vulnerable repository** under Cloud Run Sandbox → signed blocking evidence → private A2A → **NO_GO**.
8. Under the same release/provenance chain, run the **fixed repository** → clean signed evidence → private A2A → **GO**. Show Firestore prior-release context and the Cloud Trace containing all Python and Go spans.

Key line: **Policy + verified machine evidence decide; agents, registry, memory and telemetry can explain or observe, but cannot overrule the deterministic Gatekeeper.**
