import os
import requests
from dotenv import load_dotenv

load_dotenv()

class CloudAPI:
    def __init__(self):
        self.api_key = os.getenv("VIRUSTOTAL_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3/files/"

    def verify_virustotal(self, file_hash):
        if not self.api_key:
            return {"error": "Missing VirusTotal API key"}

        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(f"{self.base_url}{file_hash}", headers=headers, timeout=5)
            if response.status_code == 200:
                stats = response.json()["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                return {"detected": malicious > 0, "malicious_count": malicious}
            elif response.status_code == 404:
                return {"detected": False}
            else:
                return {"error": f"API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}