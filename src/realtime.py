import os
import threading
from watchfiles import watch
from src.engine import ScanEngine

class RealTimeProtection:
    def __init__(self, target_directory=None):
        self.engine = ScanEngine()
        # Par défaut, surveille le dossier Téléchargements de l'utilisateur
        self.target_directory = target_directory or os.path.join(os.path.expanduser("~"), "Downloads")
        self._is_running = False

    def start_monitoring(self, callback_log=None):
        """Lance la surveillance en temps réel."""
        self._is_running = True
        
        def monitor():
            if callback_log:
                callback_log(f"[*] Real-time protection active on: {self.target_directory}")
            
            try:
                for changes in watch(self.target_directory):
                    if not self._is_running:
                        break
                    for change, path in changes:
                        # change 1 = Ajout/Création d'un fichier, 2 = Modification
                        if change in (1, 2) and os.path.isfile(path):
                            if callback_log:
                                callback_log(f"[RTP] New file detected, scanning: {os.path.basename(path)}")
                            
                            # Scan immédiat du fichier
                            result = self.engine.scan_file(path)
                            if result['status'] == 'threat':
                                if callback_log:
                                    callback_log(f"[ALERTE RTP] Threat blocked & isolated: {path} (Source: {result['source']})")
                            else:
                                if callback_log:
                                    callback_log(f"[RTP] File clean: {os.path.basename(path)}")
            except Exception as e:
                if callback_log:
                    callback_log(f"[!] RTP Error: {str(e)}")

        # Exécution dans un thread indépendant pour ne pas bloquer l'interface graphique
        self.thread = threading.Thread(target=monitor, daemon=True)
        self.thread.start()

    def stop_monitoring(self):
        self._is_running = False