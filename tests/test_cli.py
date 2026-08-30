import json
import os
import subprocess
import sys
from pathlib import Path

from release_sentinel import __version__

ROOT = Path(__file__).parents[1]


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "release_sentinel.interfaces.cli", *args],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_demo_cli_outputs_no_go():
    process = _run_cli("demo")
    assert process.returncode == 2
    body = json.loads(process.stdout)
    assert body["decision"] == "NO_GO"
    assert body["policy_id"] == "demo-release-policy"


def test_version():
    process = _run_cli("--version")
    assert process.returncode == 0
    assert process.stdout.strip() == __version__
