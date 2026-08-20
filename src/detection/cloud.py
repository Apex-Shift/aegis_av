"""Cloud threat intelligence (VirusTotal + MalwareBazaar)."""

from __future__ import annotations

import os
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()


class CloudIntelligence:
    def __init__(self) -> None:
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.vt_url = "https://www.virustotal.com/api/v3/files/"
        self.mb_url = "https://mb-api.abuse.ch/api/v1/"

    def virustotal(self, file_hash: str) -> dict[str, Any]:
        if not self.vt_key:
            return {"detected": False, "error": "No VT API key"}
        try:
            r = requests.get(
                f"{self.vt_url}{file_hash}",
                headers={"x-apikey": self.vt_key},
                timeout=8,
            )
            if r.status_code == 200:
                stats = r.json()["data"]["attributes"]["last_analysis_stats"]
                mal = stats.get("malicious", 0)
                return {
                    "detected": mal > 0,
                    "malicious": mal,
                    "suspicious": stats.get("suspicious", 0),
                    "source": "virustotal",
                }
            if r.status_code == 404:
                return {"detected": False, "source": "virustotal"}
            return {"detected": False, "error": f"HTTP {r.status_code}"}
        except Exception as e:
            return {"detected": False, "error": str(e)}

    def malwarebazaar(self, file_hash: str) -> dict[str, Any]:
        try:
            r = requests.post(
                self.mb_url,
                data={"query": "get_info", "hash": file_hash},
                timeout=8,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("query_status") == "ok":
                    sig = data.get("data", [{}])[0].get("signature", "malware")
                    return {"detected": True, "signature": sig, "source": "malwarebazaar"}
            return {"detected": False, "source": "malwarebazaar"}
        except Exception as e:
            return {"detected": False, "error": str(e)}

    def check(self, file_hash: str, use_vt: bool = True) -> dict[str, Any]:
        """Query available cloud sources. Prefer MalwareBazaar first (no key needed)."""
        mb = self.malwarebazaar(file_hash)
        if mb.get("detected"):
            return mb
        if use_vt and self.vt_key:
            return self.virustotal(file_hash)
        return {"detected": False}
