"""High-performance hashing utilities."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterator


def sha256_file(path: str | Path, chunk_size: int = 1024 * 1024) -> str | None:
    """Compute SHA-256 of a file. Returns None on I/O error."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, IOError):
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_files(root: str | Path, extensions: set[str] | None = None) -> Iterator[Path]:
    """Yield files under root, optionally filtered by extension."""
    root = Path(root)
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_file():
            if extensions is None or p.suffix.lower() in extensions:
                yield p
