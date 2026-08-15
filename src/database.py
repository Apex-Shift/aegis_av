import json
import os

class Database:
    def __init__(self, base_path="data/viral_base.json"):
        self.base_path = base_path
        self.signatures = self.load_database()

    def load_database(self):
        if not os.path.exists(self.base_path):
            os.makedirs(os.path.dirname(self.base_path), exist_ok=True)
            return {"hashes": []}
        try:
            with open(self.base_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {"hashes": []}

    def is_locally_malicious(self, file_hash):
        return file_hash in self.signatures.get("hashes", [])

    def update_database(self, new_hashes):
        """Ajoute de nouveaux hashs à la base locale."""
        current_hashes = self.signatures.get("hashes", [])
        added_count = 0
        for h in new_hashes:
            if h not in current_hashes:
                current_hashes.append(h)
                added_count += 1
        
        self.signatures["hashes"] = current_hashes
        os.makedirs(os.path.dirname(self.base_path), exist_ok=True)
        with open(self.base_path, "w", encoding="utf-8") as f:
            json.dump(self.signatures, f, indent=4)
        return added_count