"""YARA static analysis engine."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class YaraEngine:
    def __init__(self, rules_dir: str | Path = "data/yara_rules") -> None:
        self.rules_dir = Path(rules_dir)
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self._rules = None
        self._ensure_default_rules()
        self.compile()

    def _ensure_default_rules(self) -> None:
        default = self.rules_dir / "aegis_default.yar"
        if not default.exists():
            default.write_text(
                '''
rule Aegis_Suspicious_Strings
{
    meta:
        description = "Generic suspicious patterns"
        author = "AegisAV"
    strings:
        $a = "CreateRemoteThread" ascii wide
        $b = "VirtualAllocEx" ascii wide
        $c = "WriteProcessMemory" ascii wide
        $d = "powershell -enc" ascii wide nocase
        $e = "cmd.exe /c" ascii wide nocase
        $f = "This program cannot be run in DOS mode" ascii
    condition:
        2 of them
}

rule Aegis_EICAR
{
    meta:
        description = "EICAR test file"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
''',
                encoding="utf-8",
            )

    def compile(self) -> bool:
        if not YARA_AVAILABLE:
            return False
        filepaths = {}
        for f in self.rules_dir.glob("*.yar*"):
            filepaths[f.name] = str(f)
        if not filepaths:
            return False
        try:
            self._rules = yara.compile(filepaths=filepaths)
            return True
        except Exception as e:
            print(f"[YARA] Compile error: {e}")
            self._rules = None
            return False

    def scan(self, path: str | Path) -> dict[str, Any]:
        if not self._rules:
            return {"matched": False, "rules": []}
        try:
            matches = self._rules.match(str(path))
            if matches:
                return {
                    "matched": True,
                    "rules": [m.rule for m in matches],
                    "meta": [dict(m.meta) for m in matches],
                }
        except Exception:
            pass
        return {"matched": False, "rules": []}
