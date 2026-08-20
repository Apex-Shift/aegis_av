"""AES-encrypted quarantine system."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet


class Quarantine:
    def __init__(self, directory: str | Path = "data/quarantine") -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.key_file = self.dir / "secret.key"
        self.meta_file = self.dir / "metadata.json"
        self._key = self._load_or_create_key()
        self._fernet = Fernet(self._key)
        self._meta = self._load_meta()

    def _load_or_create_key(self) -> bytes:
        if self.key_file.exists():
            return self.key_file.read_bytes()
        key = Fernet.generate_key()
        self.key_file.write_bytes(key)
        return key

    def _load_meta(self) -> dict[str, Any]:
        if self.meta_file.exists():
            try:
                return json.loads(self.meta_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_meta(self) -> None:
        self.meta_file.write_text(json.dumps(self._meta, indent=2), encoding="utf-8")

    def isolate(self, path: str | Path, reason: str = "threat", source: str = "unknown") -> str | None:
        """Encrypt and quarantine a file. Returns quarantine ID or None."""
        path = Path(path)
        if not path.is_file():
            return None
        try:
            data = path.read_bytes()
            encrypted = self._fernet.encrypt(data)
            qid = str(uuid.uuid4())
            qpath = self.dir / f"{qid}.lock"
            qpath.write_bytes(encrypted)

            self._meta[qid] = {
                "original_path": str(path),
                "filename": path.name,
                "reason": reason,
                "source": source,
                "quarantined_at": datetime.utcnow().isoformat() + "Z",
                "size": len(data),
            }
            self._save_meta()
            path.unlink(missing_ok=True)
            return qid
        except Exception:
            return None

    def restore(self, qid: str) -> bool:
        """Decrypt and restore a quarantined file to its original path."""
        info = self._meta.get(qid)
        if not info:
            return False
        qpath = self.dir / f"{qid}.lock"
        if not qpath.exists():
            return False
        try:
            decrypted = self._fernet.decrypt(qpath.read_bytes())
            dest = Path(info["original_path"])
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(decrypted)
            qpath.unlink()
            del self._meta[qid]
            self._save_meta()
            return True
        except Exception:
            return False

    def list_items(self) -> list[dict[str, Any]]:
        return [{"id": k, **v} for k, v in self._meta.items()]

    def delete(self, qid: str) -> bool:
        info = self._meta.pop(qid, None)
        if not info:
            return False
        qpath = self.dir / f"{qid}.lock"
        qpath.unlink(missing_ok=True)
        self._save_meta()
        return True
