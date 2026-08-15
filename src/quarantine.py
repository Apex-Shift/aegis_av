import os
import json
import uuid
from cryptography.fernet import Fernet

class Quarantine:
    def __init__(self, quarantine_dir="data/quarantine"):
        self.quarantine_dir = quarantine_dir
        self.meta_file = os.path.join(quarantine_dir, "metadata.json")
        self.key_file = os.path.join(quarantine_dir, "secret.key")
        self._initialize()

    def _initialize(self):
        os.makedirs(self.quarantine_dir, exist_ok=True)
        if not os.path.exists(self.key_file):
            self.key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(self.key)
        else:
            with open(self.key_file, "rb") as f:
                self.key = f.read()
        
        if not os.path.exists(self.meta_file):
            with open(self.meta_file, "w", encoding="utf-8") as f:
                json.dump({}, f)

    def isolate_file(self, original_path):
        """Encrypts and moves a malicious file to quarantine."""
        if not os.path.exists(original_path):
            return False

        f = Fernet(self.key)
        with open(original_path, "rb") as file_to_read:
            original_data = file_to_read.read()

        encrypted_data = f.encrypt(original_data)
        
        file_id = str(uuid.uuid4())
        quarantine_path = os.path.join(self.quarantine_dir, f"{file_id}.lock")

        with open(quarantine_path, "wb") as file_to_write:
            file_to_write.write(encrypted_data)

        # Save metadata
        with open(self.meta_file, "r", encoding="utf-8") as meta_f:
            meta = json.load(meta_f)

        meta[file_id] = {
            "original_path": original_path,
            "filename": os.path.basename(original_path)
        }

        with open(self.meta_file, "w", encoding="utf-8") as meta_f:
            json.dump(meta, meta_f, indent=4)

        # Remove original file
        try:
            os.remove(original_path)
            return True
        except Exception:
            return False