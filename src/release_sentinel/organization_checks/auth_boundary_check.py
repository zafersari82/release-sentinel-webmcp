from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_app(repository: Path):
    app_path = (repository / "app.py").resolve()
    if repository.resolve() not in [app_path.parent, *app_path.parents] or not app_path.is_file():
        raise RuntimeError("app.py missing from reviewed repository")
    spec = importlib.util.spec_from_file_location("reviewed_repository_app", app_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load reviewed application module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    repository = Path.cwd().resolve()
    module = _load_app(repository)
    checker = getattr(module, "can_read", None)
    if not callable(checker):
        print(json.dumps({"check": "auth-boundary", "result": "invalid-interface"}, sort_keys=True))
        return 2
    expected = False
    actual = bool(checker("tenant-a", "tenant-b"))
    print(json.dumps({"check": "auth-boundary", "expected": expected, "actual": actual}, sort_keys=True))
    return 0 if actual is expected else 1


if __name__ == "__main__":
    raise SystemExit(main())
