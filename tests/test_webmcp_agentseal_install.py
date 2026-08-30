from pathlib import Path
import tomllib

ROOT = Path(__file__).parents[1]


def test_dev_extra_never_resolves_agentseal_from_pypi():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    dev = data["project"]["optional-dependencies"]["dev"]
    assert not any(item.strip().lower().startswith("agentseal") for item in dev)


def test_readme_installs_repo_local_agentseal_explicitly():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "pip install -e packages/agentseal -e '.[dev]'" in readme
