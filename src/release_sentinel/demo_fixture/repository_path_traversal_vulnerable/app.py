from pathlib import Path


def resolve_export(root: Path, user_path: str) -> Path:
    """Deliberately vulnerable fixture: traversal is not contained."""
    return root / user_path
