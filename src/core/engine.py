"""AegisAV multi-layer scan engine."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from src.detection.cloud import CloudIntelligence
from src.detection.database import SignatureDatabase
from src.detection.yara_engine import YaraEngine
from src.protection.quarantine import Quarantine
from src.utils.hashing import iter_files, sha256_file


class ScanEngine:
    def __init__(
        self,
        use_cloud: bool = True,
        use_yara: bool = True,
        auto_quarantine: bool = True,
    ) -> None:
        self.db = SignatureDatabase()
        self.yara = YaraEngine() if use_yara else None
        self.cloud = CloudIntelligence() if use_cloud else None
        self.quarantine = Quarantine()
        self.auto_quarantine = auto_quarantine

    def scan_file(self, path: str | Path, offline: bool = False) -> dict[str, Any]:
        path = Path(path)
        result: dict[str, Any] = {
            "path": str(path),
            "status": "clean",
            "hash": None,
            "source": None,
            "details": {},
        }

        file_hash = sha256_file(path)
        if not file_hash:
            result["status"] = "error"
            result["details"] = {"error": "unreadable"}
            return result
        result["hash"] = file_hash

        # Layer 1 – Local signatures
        if self.db.is_malicious(file_hash):
            info = self.db.get_info(file_hash) or {}
            result.update(status="threat", source="local_database", details=info)
            if self.auto_quarantine:
                self.quarantine.isolate(path, reason="local_signature", source="local_database")
            return result

        # Layer 2 – YARA
        if self.yara:
            yara_res = self.yara.scan(path)
            if yara_res.get("matched"):
                result.update(
                    status="threat",
                    source="yara",
                    details={"rules": yara_res.get("rules", [])},
                )
                if self.auto_quarantine:
                    self.quarantine.isolate(path, reason="yara_match", source="yara")
                return result

        # Layer 3 – Cloud (skip in pure offline mode)
        if not offline and self.cloud:
            cloud_res = self.cloud.check(file_hash)
            if cloud_res.get("detected"):
                result.update(
                    status="threat",
                    source=cloud_res.get("source", "cloud"),
                    details=cloud_res,
                )
                if self.auto_quarantine:
                    self.quarantine.isolate(
                        path, reason="cloud_detection", source=cloud_res.get("source", "cloud")
                    )
                return result

        return result

    def scan_path(
        self,
        root: str | Path,
        offline: bool = False,
        max_workers: int = 6,
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> list[dict[str, Any]]:
        files = list(iter_files(root))
        total = len(files)
        results: list[dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(self.scan_file, f, offline): f for f in files}
            done = 0
            for fut in as_completed(futures):
                res = fut.result()
                results.append(res)
                done += 1
                if progress_cb:
                    progress_cb(done, total, res.get("path", ""))
        return results

    def forensic_scan(self, root: str | Path, max_workers: int = 4) -> dict[str, Any]:
        """
        Offline forensic mode:
        - No cloud lookups
        - Collects hashes + YARA hits
        - Does NOT auto-quarantine (read-only analysis)
        """
        old = self.auto_quarantine
        self.auto_quarantine = False
        results = self.scan_path(root, offline=True, max_workers=max_workers)
        self.auto_quarantine = old

        threats = [r for r in results if r["status"] == "threat"]
        errors = [r for r in results if r["status"] == "error"]
        return {
            "mode": "forensic",
            "scanned": len(results),
            "threats": len(threats),
            "errors": len(errors),
            "threat_list": threats,
            "results": results,
        }
