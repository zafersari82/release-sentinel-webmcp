from pathlib import Path


def resolve_export(root: Path, user_path: str) -> Path:
    """Contain exports inside the package-owned root."""
    resolved_root = root.resolve()
    candidate = (resolved_root / user_path).resolve()
    if candidate != resolved_root and resolved_root not in candidate.parents:
        raise ValueError("path escapes export root")
    return candidate
