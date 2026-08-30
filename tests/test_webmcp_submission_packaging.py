from pathlib import Path
import tomllib

ROOT = Path(__file__).parents[1]


def test_single_service_webmcp_docker_contract():
    dockerfile = (ROOT / 'Dockerfile.webmcp').read_text(encoding='utf-8')
    entrypoint = (ROOT / 'deploy/webmcp-entrypoint.sh').read_text(encoding='utf-8')

    assert 'FROM golang:1.23' in dockerfile
    assert 'go build -trimpath -o /out/release-sentinel-gatekeeper ./cmd/gatekeeper' in dockerfile
    assert 'FROM python:3.13-slim' in dockerfile
    assert 'openssl' in dockerfile
    assert 'release-sentinel-gatekeeper' in dockerfile
    assert 'webmcp-entrypoint.sh' in dockerfile

    assert 'RELEASE_SENTINEL_DEMO_SIGNING_KEY' in entrypoint
    assert 'RELEASE_SENTINEL_EVIDENCE_PUBLIC_KEY_PATH' in entrypoint
    assert 'RELEASE_SENTINEL_EVIDENCE_KEY_ID=local-demo-ephemeral-key' in entrypoint
    assert 'RELEASE_SENTINEL_GATEKEEPER_URL=http://127.0.0.1:9090' in entrypoint
    assert 'RELEASE_SENTINEL_WEBMCP_JUDGED_MODE=1' in entrypoint
    assert 'PORT=9090' in entrypoint
    assert '/usr/local/bin/release-sentinel-gatekeeper' in entrypoint
    assert 'uvicorn release_sentinel.interfaces.api:app' in entrypoint


def test_browser_acceptance_dependency_is_declared():
    data = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))
    browser = data['project']['optional-dependencies']['browser']
    assert any(item.startswith('playwright>=') for item in browser)


def test_browser_acceptance_uses_playwright_managed_chromium():
    script = (ROOT / 'tests/browser_webmcp_acceptance.py').read_text(encoding='utf-8')
    assert 'PLAYWRIGHT_CHROMIUM_EXECUTABLE' in script
    assert 'playwright.chromium.launch(**launch_options)' in script
    assert "launch_options = {'headless': True" in script


def test_ci_builds_and_smoke_tests_the_submission_container():
    workflow = (ROOT / '.github/workflows/trust-gates.yml').read_text(encoding='utf-8')
    assert 'WebMCP submission container' in workflow
    assert 'docker build -f Dockerfile.webmcp' in workflow
    assert 'docker run -d --name release-sentinel-webmcp-ci' in workflow
    assert '/v1/webmcp/tools' in workflow
    assert '/v1/webmcp/attack/force_agents_go' in workflow
    assert 'DETERMINISTIC_GO_GATEKEEPER' in workflow
    assert 'browser_webmcp_acceptance.py' in workflow


def test_render_blueprint_targets_the_webmcp_judge_container():
    blueprint = (ROOT / 'render.yaml').read_text(encoding='utf-8')
    assert 'type: web' in blueprint
    assert 'runtime: docker' in blueprint
    assert 'plan: free' in blueprint
    assert 'dockerfilePath: ./Dockerfile.webmcp' in blueprint
    assert 'dockerContext: .' in blueprint
    assert 'healthCheckPath: /v1/webmcp/tools' in blueprint
    assert 'autoDeployTrigger: checksPass' in blueprint


def test_submission_repo_does_not_ship_internal_or_stale_bundle_material():
    assert not (ROOT / 'history').exists()
    assert not (ROOT / 'docs/superpowers').exists()
    assert not (ROOT / 'FREEZE_MANIFEST.txt').exists()
    assert not (ROOT / 'scripts/verify-release-bundle.sh').exists()
    assert not (ROOT / 'dist').exists()
    ignore = (ROOT / '.gitignore').read_text(encoding='utf-8')
    assert '.pytest_cache/' in ignore
    assert not (ROOT / 'artifacts/attack-the-gate-1440x900.png').exists()
    assert not (ROOT / 'artifacts/enterprise-control-plane-1440x900.png').exists()


def test_public_submission_uses_current_provenance_and_webmcp_framing():
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    arena = (ROOT / 'src/release_sentinel/interfaces/static/arena.html').read_text(encoding='utf-8')
    provenance_path = ROOT / 'CHALLENGE_PROVENANCE.md'

    assert provenance_path.exists()
    assert not (ROOT / 'PREEXISTING_WORK.md').exists()
    assert 'PRE-EXISTING v2.3.0 CORE' not in arena
    assert 'CAPABILITY WITHOUT AUTHORITY · WEBMCP PROOF ARENA' in arena
    assert 'run_attack_suite' in readme
    assert 'exactly 12 typed tools' in readme
    assert 'PREEXISTING_WORK.md' not in readme

    provenance = provenance_path.read_text(encoding='utf-8')
    assert '634c8fbfb9697169cdb76fe4b3c5f52cf5295b039b22a29dec02da8a3af3c967' in provenance
    assert 'Release Sentinel predates the WebMCP Challenge' in provenance
    assert 'Release Sentinel predates the WebMCP Challenge' in readme
    assert '2026-08-20' in provenance
    assert '2026-08-21' in provenance
    assert 'deterministic release decision boundary' in provenance
    assert 'Coverage Arena' in provenance
    assert 'Challenge-period WebMCP work was carried out during the official Submission Period.' in provenance
    assert 'public challenge repository was created on **August 29, 2026**' in provenance
    assert 'public implementation history is dated within the Submission Period' in provenance
