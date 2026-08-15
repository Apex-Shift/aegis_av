import os
import yara

class YaraScanner:
    def __init__(self, rules_dir="data/yara_rules"):
        self.rules_dir = rules_dir
        self.compiled_rules = self.compile_rules()

    def compile_rules(self):
        """Compile toutes les règles YARA présentes dans le dossier."""
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            # Création d'une règle YARA de test par défaut
            default_rule = """
            rule Suspicious_Keyword {
                meta:
                    description = "Detects generic suspicious patterns"
                strings:
                    $malicious_string = "malware_test_string"
                condition:
                    $malicious_string
            }
            """
            with open(os.path.join(self.rules_dir, "test_rule.yar"), "w", encoding="utf-8") as f:
                f.write(default_rule)

        filepaths = {}
        for file in os.listdir(self.rules_dir):
            if file.endswith(".yar") or file.endswith(".yara"):
                filepaths[file] = os.path.join(self.rules_dir, file)

        if not filepaths:
            return None

        try:
            return yara.compile(filepaths=filepaths)
        except Exception as e:
            print(f"Error compiling YARA rules: {e}")
            return None

    def scan_file(self, file_path):
        """Scanne un fichier avec les règles YARA compilées."""
        if not self.compiled_rules:
            return {"matched": False}
        try:
            matches = self.compiled_rules.match(file_path)
            if matches:
                return {"matched": True, "rules": [m.rule for m in matches]}
        except Exception:
            pass
        return {"matched": False}