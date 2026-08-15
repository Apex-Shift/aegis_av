import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from src.database import Database
from src.cloud_api import CloudAPI
from src.malware_bazaar import MalwareBazaarAPI
from src.yara_scanner import YaraScanner
from src.quarantine import Quarantine

class ScanEngine:
    def __init__(self):
        self.db = Database()
        self.cloud = CloudAPI()
        self.mb_api = MalwareBazaarAPI()
        self.yara_scanner = YaraScanner()
        self.quarantine = Quarantine()

    def calculate_sha256(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except IOError:
            return None

    def scan_file(self, file_path):
        file_hash = self.calculate_sha256(file_path)
        if not file_hash:
            return {"status": "error", "path": file_path}

        # 1. Vérification Locale (Signatures ClamAV / JSON)
        if self.db.is_locally_malicious(file_hash):
            self.quarantine.isolate_file(file_path)
            return {"status": "threat", "source": "local_database", "path": file_path}

        # 2. Vérification par Analyse Statique YARA
        yara_res = self.yara_scanner.scan_file(file_path)
        if yara_res.get("matched"):
            self.quarantine.isolate_file(file_path)
            return {"status": "threat", "source": "yara_rules", "path": file_path}

        # 3. Vérification MalwareBazaar (Hashes très récents)
        mb_res = self.mb_api.query_hash(file_hash)
        if mb_res.get("detected"):
            self.quarantine.isolate_file(file_path)
            return {"status": "threat", "source": "malware_bazaar", "path": file_path}

        # 4. Vérification Cloud VirusTotal (En secours)
        cloud_res = self.cloud.verify_virustotal(file_hash)
        if cloud_res.get("detected"):
            self.quarantine.isolate_file(file_path)
            return {"status": "threat", "source": "virustotal", "path": file_path}

        return {"status": "clean", "path": file_path, "hash": file_hash}

    def scan_directory_parallel(self, directory_path, max_workers=4):
        files_to_scan = []
        for root, _, files in os.walk(directory_path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))

        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(self.scan_file, files_to_scan))
        return results