import ast
import re
from pathlib import Path

ROOT = Path(__file__).parents[1]
SRC = ROOT / "src/release_sentinel"


def test_no_legacy_manifest_ingestion_module():
    assert not (SRC / "release/test_results.py").exists()
    source = "\n".join(path.read_text(errors="ignore") for path in SRC.rglob("*.py"))
    assert "ingest_test_manifest" not in source


def test_demo_repo_has_no_release_sentinel_metadata():
    repository = SRC / "demo_fixture/repository_vulnerable"
    assert not (repository / ".release-sentinel").exists()


def test_runtime_has_bounded_contexts_not_flat_modules():
    flat_modules = [
        path.name
        for path in SRC.glob("*.py")
        if path.name != "__init__.py"
    ]
    assert flat_modules == []


def test_no_old_version_markers_in_runtime():
    source = "\n".join(path.read_text(errors="ignore") for path in SRC.rglob("*.py"))
    assert not re.search(r"v0\.\d+|0\.16\.0|test-results\.json", source)


def test_policy_and_judge_are_separate_modules():
    assert (SRC / "policy/model.py").exists()
    assert (SRC / "release/judge.py").exists()


def _internal_import_graph():
    modules = {}
    for path in SRC.rglob("*.py"):
        relative = path.relative_to(SRC).with_suffix("")
        name = "release_sentinel." + ".".join(relative.parts)
        if name.endswith(".__init__"):
            name = name[:-9]
        modules[name] = path

    graph = {name: set() for name in modules}
    for name, path in modules.items():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.ImportFrom) and node.module:
                targets.append(node.module)
            elif isinstance(node, ast.Import):
                targets.extend(alias.name for alias in node.names)

            for target in targets:
                if not target.startswith("release_sentinel"):
                    continue
                while target and target not in modules:
                    target = target.rsplit(".", 1)[0] if "." in target else ""
                if target in modules and target != name:
                    graph[name].add(target)
    return graph


def test_internal_import_graph_has_no_cycles():
    graph = _internal_import_graph()
    visiting = set()
    visited = set()

    def visit(name):
        if name in visiting:
            raise AssertionError(f"import cycle at {name}")
        if name in visited:
            return
        visiting.add(name)
        for dependency in graph[name]:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)

    for module in graph:
        visit(module)


def test_runtime_modules_stay_small_and_bounded():
    offenders = []
    for path in SRC.rglob("*.py"):
        if path.name == "__init__.py":
            continue
        line_count = len(path.read_text().splitlines())
        if line_count > 320:
            offenders.append((str(path.relative_to(SRC)), line_count))
    assert offenders == []


def test_demo_fixtures_contain_no_self_declared_evidence_metadata():
    forbidden = {"test-results.json", "test-plan.json", "auth-boundary.json"}
    for name in ("repository_vulnerable", "repository_fixed"):
        repository = SRC / "demo_fixture" / name
        assert not any(
            path.name in forbidden
            for path in repository.rglob("*")
            if path.is_file()
        )


def test_cloud_deploy_contract_is_single_path():
    deploy = ROOT / "deploy"
    assert (deploy / "e2e-cloud.sh").exists()
    assert (deploy / "cloud-proof.sh").exists()

    scripts = "\n".join(path.read_text() for path in deploy.glob("*.sh"))
    assert "--sandbox-launcher" in scripts
    assert "roles/cloudkms.signer" in scripts
    assert "CLOUD TRUST PROOF PASS" in scripts


def test_go_gatekeeper_is_separate_and_contains_no_llm_dependency():
    gatekeeper = ROOT / "gatekeeper"
    assert (gatekeeper / "go.mod").exists()
    assert (gatekeeper / "cmd/gatekeeper/main.go").exists()

    module = (gatekeeper / "go.mod").read_text().lower()
    source = "\n".join(path.read_text().lower() for path in gatekeeper.rglob("*.go"))

    assert "google.golang.org" not in module
    assert "openai" not in module
    assert "anthropic" not in module
    assert "gemini" not in module
    assert "agentinfluence" in source or "agent_influence" in source
