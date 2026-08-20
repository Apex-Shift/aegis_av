"""Real-time file system monitoring."""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Callable

from src.core.engine import ScanEngine

try:
    from watchfiles import watch
    WATCHFILES_AVAILABLE = True
except ImportError:
    WATCHFILES_AVAILABLE = False


class RealTimeProtection:
    def __init__(self, watch_dir: str | Path | None = None) -> None:
        self.watch_dir = Path(watch_dir or Path.home() / "Downloads")
        self.engine = ScanEngine(use_cloud=True, auto_quarantine=True)
        self._running = False
        self._thread: threading.Thread | None = None
        self._log: Callable[[str], None] | None = None

    def start(self, log_callback: Callable[[str], None] | None = None) -> bool:
        if not WATCHFILES_AVAILABLE:
            if log_callback:
                log_callback("[!] watchfiles not installed – RTP disabled")
            return False
        if self._running:
            return True
        self._log = log_callback
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        if self._log:
            self._log(f"[*] Real-Time Protection active on: {self.watch_dir}")
        return True

    def stop(self) -> None:
        self._running = False
        if self._log:
            self._log("[-] Real-Time Protection stopped")

    def _loop(self) -> None:
        try:
            for changes in watch(self.watch_dir):
                if not self._running:
                    break
                for change_type, path in changes:
                    # 1 = added, 2 = modified
                    if change_type in (1, 2) and os.path.isfile(path):
                        name = os.path.basename(path)
                        if self._log:
                            self._log(f"[RTP] Scanning new/modified file: {name}")
                        result = self.engine.scan_file(path)
                        if result["status"] == "threat":
                            if self._log:
                                self._log(
                                    f"[ALERT] Threat isolated: {name} "
                                    f"(source: {result.get('source')})"
                                )
                        else:
                            if self._log:
                                self._log(f"[RTP] Clean: {name}")
        except Exception as e:
            if self._log:
                self._log(f"[!] RTP error: {e}")
