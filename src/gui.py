import os
import threading
import customtkinter as ctk
from tkinter import filedialog
import psutil
from src.engine import ScanEngine
from src.database import Database
from src.realtime import RealTimeProtection

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class AegisGUI(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("AegisAV - Security Suite (Expert Edition)")
        self.geometry("1000x650")
        self.resizable(False, False)

        self.engine = ScanEngine()
        self.db = Database()
        
        # Initialisation de la protection en temps réel
        self.rtp = RealTimeProtection()
        
        self.setup_ui()

        # Démarrage automatique de la protection en temps réel au lancement
        self.rtp.start_monitoring(callback_log=self.log_global)

    def setup_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ==================== SIDEBAR ====================
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        self.logo = ctk.CTkLabel(self.sidebar, text="🛡️ AEGIS-AV", font=ctk.CTkFont(size=22, weight="bold"))
        self.logo.pack(padx=20, pady=30)

        # Boutons du menu
        self.btn_dash = ctk.CTkButton(self.sidebar, text="🏠 Dashboard", command=lambda: self.show_frame("dashboard"), fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w")
        self.btn_dash.pack(padx=15, pady=5, fill="x")

        self.btn_custom = ctk.CTkButton(self.sidebar, text="🔍 Custom Scan", command=lambda: self.show_frame("custom"), fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w")
        self.btn_custom.pack(padx=15, pady=5, fill="x")

        self.btn_volumes = ctk.CTkButton(self.sidebar, text="💾 System Volumes", command=lambda: self.show_frame("volumes"), fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w")
        self.btn_volumes.pack(padx=15, pady=5, fill="x")

        self.btn_update = ctk.CTkButton(self.sidebar, text="🔄 Database Update", command=lambda: self.show_frame("update"), fg_color="transparent", text_color=("gray10", "gray90"), hover_color=("gray70", "gray30"), anchor="w")
        self.btn_update.pack(padx=15, pady=5, fill="x")

        # ==================== CONTAINER PRINCIPAL ====================
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.frames = {}
        self.init_dashboard_frame()
        self.init_custom_frame()
        self.init_volumes_frame()
        self.init_update_frame()

        self.show_frame("dashboard")

    def show_frame(self, name):
        frame = self.frames[name]
        frame.tkraise()

    # ==================== 1. DASHBOARD ====================
    def init_dashboard_frame(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew")

        header = ctk.CTkLabel(frame, text="Security Status", font=ctk.CTkFont(size=20, weight="bold"))
        header.pack(anchor="w", pady=(10, 15))

        status_card = ctk.CTkFrame(frame, height=140, corner_radius=10)
        status_card.pack(fill="x", pady=5)
        status_card.pack_propagate(False)

        self.dash_status_label = ctk.CTkLabel(status_card, text="Your computer is fully protected", font=ctk.CTkFont(size=22, weight="bold"), text_color="#2ecc71")
        self.dash_status_label.pack(anchor="w", padx=25, pady=20)

        # Interrupteur Real-Time Protection (RTP)
        self.rtp_switch = ctk.CTkSwitch(status_card, text="Real-Time Protection", command=self.toggle_rtp, progress_color="#00A86B")
        self.rtp_switch.pack(anchor="w", padx=25, pady=(0, 20))
        self.rtp_switch.select()  # Activé par défaut

        # Console / Logs globaux
        self.dash_log = ctk.CTkTextbox(frame, height=280, corner_radius=8)
        self.dash_log.pack(fill="both", expand=True, pady=15)
        self.dash_log.insert("0.0", "[*] AegisAV Real-time engine loaded successfully.\n")
        self.dash_log.configure(state="disabled")

        self.frames["dashboard"] = frame

    def toggle_rtp(self):
        if self.rtp_switch.get() == 1:
            self.rtp.start_monitoring(callback_log=self.log_global)
            self.log_global("[+] Real-Time Protection enabled.")
        else:
            self.rtp.stop_monitoring()
            self.log_global("[-] Real-Time Protection disabled.")

    def log_global(self, msg):
        self.dash_log.configure(state="normal")
        self.dash_log.insert("end", msg + "\n")
        self.dash_log.see("end")
        self.dash_log.configure(state="disabled")

    # ==================== 2. CUSTOM SCAN ====================
    def init_custom_frame(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew")

        header = ctk.CTkLabel(frame, text="Custom File / Folder Scan", font=ctk.CTkFont(size=20, weight="bold"))
        header.pack(anchor="w", pady=(10, 15))

        desc = ctk.CTkLabel(frame, text="Select a specific file or folder to perform a deep multi-layer analysis.", font=ctk.CTkFont(size=13), text_color="gray")
        desc.pack(anchor="w", pady=(0, 20))

        btn_select = ctk.CTkButton(frame, text="Browse & Scan Target", command=self.start_custom_scan, fg_color="#00A86B", hover_color="#008253", height=40)
        btn_select.pack(anchor="w", pady=10)

        self.custom_progress = ctk.CTkProgressBar(frame)
        self.custom_progress.pack(fill="x", pady=20)
        self.custom_progress.set(0)

        self.custom_log = ctk.CTkTextbox(frame, height=280, corner_radius=8)
        self.custom_log.pack(fill="both", expand=True, pady=10)
        self.custom_log.insert("0.0", "[*] Ready for targeted inspection.\n")
        self.custom_log.configure(state="disabled")

        self.frames["custom"] = frame

    def start_custom_scan(self):
        path = filedialog.askdirectory(title="Select folder to scan")
        if not path:
            path = filedialog.askopenfilename(title="Select file to scan")
        
        if path:
            self.custom_progress.set(0)
            threading.Thread(target=self.run_custom_scan_thread, args=(path,), daemon=True).start()

    def run_custom_scan_thread(self, path):
        self.custom_log.configure(state="normal")
        self.custom_log.insert("end", f"\n--- Scanning target: {path} ---\n")
        self.custom_log.configure(state="disabled")

        if os.path.isfile(path):
            res = self.engine.scan_file(path)
            self.custom_log.configure(state="normal")
            self.custom_log.insert("end", f"[{res['status'].upper()}] {path}\n")
            self.custom_log.configure(state="disabled")
            self.custom_progress.set(1.0)
        elif os.path.isdir(path):
            results = self.engine.scan_directory_parallel(path)
            total = len(results)
            for i, res in enumerate(results):
                self.custom_log.configure(state="normal")
                self.custom_log.insert("end", f"[{res['status'].upper()}] {res['path']}\n")
                self.custom_log.configure(state="disabled")
                if total > 0:
                    self.custom_progress.set((i + 1) / total)

        self.custom_log.configure(state="normal")
        self.custom_log.insert("end", "--- Target scan complete ---\n")
        self.custom_log.configure(state="disabled")

    # ==================== 3. SYSTEM VOLUMES ====================
    def init_volumes_frame(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew")

        header = ctk.CTkLabel(frame, text="System Volumes Management", font=ctk.CTkFont(size=20, weight="bold"))
        header.pack(anchor="w", pady=(10, 15))

        desc = ctk.CTkLabel(frame, text="Detected local drives and partitions available for full volume scanning.", font=ctk.CTkFont(size=13), text_color="gray")
        desc.pack(anchor="w", pady=(0, 20))

        self.volumes_frame = ctk.CTkScrollableFrame(frame, height=250, corner_radius=8)
        self.volumes_frame.pack(fill="both", expand=True, pady=5)

        self.refresh_volumes_list()

        btn_refresh = ctk.CTkButton(frame, text="Refresh Drives", command=self.refresh_volumes_list, fg_color="gray30", hover_color="gray40")
        btn_refresh.pack(anchor="w", pady=10)

        self.frames["volumes"] = frame

    def refresh_volumes_list(self):
        for widget in self.volumes_frame.winfo_children():
            widget.destroy()

        partitions = psutil.disk_partitions()
        for p in partitions:
            try:
                usage = psutil.disk_usage(p.mountpoint)
                free_gb = usage.free / (1024**3)
                total_gb = usage.total / (1024**3)
                percent = usage.percent
            except PermissionError:
                continue

            card = ctk.CTkFrame(self.volumes_frame, corner_radius=6)
            card.pack(fill="x", pady=5, padx=5)

            info_text = f"Drive: {p.device}  [{p.fstype}]  -  Free: {free_gb:.1f} GB / Total: {total_gb:.1f} GB ({percent}% used)"
            lbl = ctk.CTkLabel(card, text=info_text, font=ctk.CTkFont(size=13, weight="bold"))
            lbl.pack(side="left", padx=15, pady=15)

            btn_scan_vol = ctk.CTkButton(card, text="Scan Volume", width=120, fg_color="#00A86B", hover_color="#008253",
                                          command=lambda path=p.mountpoint: self.start_volume_scan(path))
            btn_scan_vol.pack(side="right", padx=15, pady=10)

    def start_volume_scan(self, mountpoint):
        self.show_frame("dashboard")
        self.log_global(f"\n[!] Starting full scan on volume: {mountpoint}")
        threading.Thread(target=self.run_volume_scan_thread, args=(mountpoint,), daemon=True).start()

    def run_volume_scan_thread(self, mountpoint):
        results = self.engine.scan_directory_parallel(mountpoint)
        threats = sum(1 for r in results if r['status'] == 'threat')
        self.log_global(f"[+] Volume scan finished for {mountpoint}. Threats found/isolated: {threats}")

    # ==================== 4. DATABASE UPDATE ====================
    def init_update_frame(self):
        frame = ctk.CTkFrame(self.container, fg_color="transparent")
        frame.grid(row=0, column=0, sticky="nsew")

        header = ctk.CTkLabel(frame, text="Virus Database & Signatures", font=ctk.CTkFont(size=20, weight="bold"))
        header.pack(anchor="w", pady=(10, 15))

        desc = ctk.CTkLabel(frame, text="Keep your local hash signatures up to date to detect emerging threats offline.", font=ctk.CTkFont(size=13), text_color="gray")
        desc.pack(anchor="w", pady=(0, 20))

        self.update_status_lbl = ctk.CTkLabel(frame, text=f"Current Local Signatures Loaded: {len(self.db.signatures.get('hashes', []))}", font=ctk.CTkFont(size=14))
        self.update_status_lbl.pack(anchor="w", pady=10)

        btn_up = ctk.CTkButton(frame, text="Check for Updates Online", command=self.perform_database_update, fg_color="#00A86B", hover_color="#008253", height=40)
        btn_up.pack(anchor="w", pady=15)

        self.frames["update"] = frame

    def perform_database_update(self):
        simulated_new_hashes = ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        added = self.db.update_database(simulated_new_hashes)
        self.update_status_lbl.configure(text=f"Current Local Signatures Loaded: {len(self.db.signatures.get('hashes', []))}")
        
        self.show_frame("dashboard")
        self.log_global(f"[+] Database updated successfully. Added new signatures: {added}")