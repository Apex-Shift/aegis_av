"""Local signature database (hash-based)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class SignatureDatabase:
    def __init__(self, path: str | Path = "data/signatures/hashes.json") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] = {"hashes": {}, "version": "2.0", "updated": None}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        if "hashes" not in self._data:
            self._data["hashes"] = {}

    def save(self) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    def is_malicious(self, file_hash: str) -> bool:
        return file_hash in self._data["hashes"]

    def get_info(self, file_hash: str) -> dict | None:
        return self._data["hashes"].get(file_hash)

    def add(self, file_hash: str, name: str = "unknown", source: str = "manual") -> bool:
        if file_hash in self._data["hashes"]:
            return False
        self._data["hashes"][file_hash] = {"name": name, "source": source}
        return True

    def add_many(self, items: list[tuple[str, str, str]]) -> int:
        """items = [(hash, name, source), ...]"""
        added = 0
        for h, name, source in items:
            if self.add(h, name, source):
                added += 1
        if added:
            self.save()
        return added

    def count(self) -> int:
        return len(self._data["hashes"])

    def update_from_list(self, hashes: list[str], source: str = "update") -> int:
        return self.add_many([(h, "unknown", source) for h in hashes])
