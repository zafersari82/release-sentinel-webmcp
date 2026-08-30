from __future__ import annotations

import re
from pathlib import Path

from release_sentinel import __version__
from release_sentinel.agents.registry import default_agent_registry

ROOT = Path(__file__).parents[1]


def test_cross_language_release_version_is_consistent():
    go = (ROOT / "gatekeeper/internal/buildinfo/version.go").read_text(encoding="utf-8")
    match = re.search(r'const Version = "([^"]+)"', go)
    assert match and match.group(1) == __version__
    assert {record.version for record in default_agent_registry().list()} == {__version__}


def test_packaging_uses_python_runtime_version_as_source_of_truth():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text
    assert 'version = {attr = "release_sentinel.__version__"}' in text
    assert re.search(r'^version\s*=\s*"', text, re.MULTILINE) is None


def test_dist_wheels_cannot_be_stale_if_bundled():
    dist = ROOT / "dist"
    if not dist.exists():
        return
    wheels = list(dist.glob("release_sentinel-*.whl"))
    assert all(f"release_sentinel-{__version__}-" in wheel.name for wheel in wheels)


def test_public_arena_image_uses_runtime_version_as_source_of_truth():
    script = (ROOT / "scripts/run-public-attack.sh").read_text(encoding="utf-8")
    assert "from release_sentinel import __version__" in script
    assert "release-sentinel-public-arena:${VERSION}" in script
    assert re.search(r"release-sentinel-public-arena:[0-9]+\.[0-9]+\.[0-9]+", script) is None


def test_coverage_arena_release_version_is_2_3_0():
    assert __version__ == "2.3.0"
