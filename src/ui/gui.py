"""AegisAV V2 – Professional GUI."""

from __future__ import annotations

import os
import threading
from tkinter import filedialog

import customtkinter as ctk
import psutil

from src.core.engine import ScanEngine
from src.detection.database import SignatureDatabase
from src.protection.realtime import RealTimeProtection

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")


class AegisGUI(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title("AegisAV — Security Suite v2")
        self.geometry("1050x680")
        self.minsize(900, 600)

        self.engine = ScanEngine()
        self.db = SignatureDatabase()
        self.rtp = RealTimeProtection()

        self._build()
        self.show_frame("dashboard")
        self.rtp.start(log_callback=self.log)

    def _build(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar
        side = ctk.CTkFrame(self, width=210, corner_radius=0)
        side.grid(row=0, column=0, sticky="nsew")
        side.grid_propagate(False)

        ctk.CTkLabel(side, text="AEGIS-AV", font=ctk.CTkFont(size=22, weight="bold")).pack(
            pady=(28, 6)
        )
        ctk.CTkLabel(side, text="v2  •  Expert Edition", text_color="#00A86B").pack(pady=(0, 20))

        for text, key in [
            ("Dashboard", "dashboard"),
            ("Custom Scan", "custom"),
            ("Forensic Mode", "forensic"),
            ("System Volumes", "volumes"),
            ("Quarantine", "quarantine"),
            ("Signatures", "update"),
        ]:
            ctk.CTkButton(
                side,
                text=text,
                anchor="w",
                fg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray70", "gray30"),
                command=lambda k=key: self.show_frame(k),
            ).pack(fill="x", padx=12, pady=3)

        # Main area
        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.grid(row=0, column=1, sticky="nsew", padx=18, pady=18)
        self.container.grid_columnconfigure(0, weight=1)
        self.container.grid_rowconfigure(0, weight=1)

        self.frames: dict[str, ctk.CTkFrame] = {}
        self._init_dashboard()
        self._init_custom()
        self._init_forensic()
        self._init_volumes()
        self._init_quarantine()
        self._init_update()

    def show_frame(self, name: str) -> None:
        self.frames[name].tkraise()

    def log(self, msg: str) -> None:
        self.dash_log.configure(state="normal")
        self.dash_log.insert("end", msg + "\n")
        self.dash_log.see("end")
        self.dash_log.configure(state="disabled")

    # ---------- Dashboard ----------
    def _init_dashboard(self) -> None:
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        f.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(f, text="Security Status", font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", pady=(0, 12)
        )

        card = ctk.CTkFrame(f, height=120, corner_radius=10)
        card.pack(fill="x")
        card.pack_propagate(False)

        self.status_lbl = ctk.CTkLabel(
            card,
            text="System protected",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#2ecc71",
        )
        self.status_lbl.pack(anchor="w", padx=20, pady=(18, 6))

        self.rtp_switch = ctk.CTkSwitch(
            card, text="Real-Time Protection", command=self._toggle_rtp, progress_color="#00A86B"
        )
        self.rtp_switch.pack(anchor="w", padx=20)
        self.rtp_switch.select()

        self.dash_log = ctk.CTkTextbox(f, height=320, font=ctk.CTkFont(family="Consolas", size=13))
        self.dash_log.pack(fill="both", expand=True, pady=14)
        self.dash_log.insert("0.0", "[*] AegisAV v2 engine ready.\n")
        self.dash_log.configure(state="disabled")

        self.frames["dashboard"] = f

    def _toggle_rtp(self) -> None:
        if self.rtp_switch.get():
            self.rtp.start(log_callback=self.log)
        else:
            self.rtp.stop()

    # ---------- Custom Scan ----------
    def _init_custom(self) -> None:
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        f.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(f, text="Custom Scan", font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", pady=(0, 8)
        )
        ctk.CTkLabel(
            f, text="Deep multi-layer scan of a file or folder (hash + YARA + cloud).", text_color="gray"
        ).pack(anchor="w", pady=(0, 14))

        ctk.CTkButton(
            f, text="Browse & Scan", height=38, fg_color="#00A86B", command=self._start_custom
        ).pack(anchor="w")

        self.custom_bar = ctk.CTkProgressBar(f)
        self.custom_bar.pack(fill="x", pady=16)
        self.custom_bar.set(0)

        self.custom_log = ctk.CTkTextbox(f, height=300, font=ctk.CTkFont(family="Consolas", size=13))
        self.custom_log.pack(fill="both", expand=True)
        self.custom_log.insert("0.0", "[*] Ready.\n")
        self.custom_log.configure(state="disabled")

        self.frames["custom"] = f

    def _start_custom(self) -> None:
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if not path:
            return
        self.custom_bar.set(0)
        threading.Thread(target=self._run_custom, args=(path,), daemon=True).start()

    def _run_custom(self, path: str) -> None:
        def progress(done, total, p):
            if total:
                self.custom_bar.set(done / total)

        def write(msg):
            self.custom_log.configure(state="normal")
            self.custom_log.insert("end", msg + "\n")
            self.custom_log.see("end")
            self.custom_log.configure(state="disabled")

        write(f"--- Scanning: {path} ---")
        if os.path.isfile(path):
            res = self.engine.scan_file(path)
            write(f"[{res['status'].upper()}] {res['path']}  source={res.get('source')}")
            self.custom_bar.set(1)
        else:
            results = self.engine.scan_path(path, progress_cb=progress)
            threats = sum(1 for r in results if r["status"] == "threat")
            write(f"--- Done. Files: {len(results)} | Threats: {threats} ---")

    # ---------- Forensic Mode ----------
    def _init_forensic(self) -> None:
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        f.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(f, text="Forensic / Offline Mode", font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", pady=(0, 8)
        )
        ctk.CTkLabel(
            f,
            text="Read-only analysis. No cloud, no quarantine. Collects hashes + YARA hits.",
            text_color="gray",
        ).pack(anchor="w", pady=(0, 14))

        ctk.CTkButton(
            f, text="Start Forensic Scan", height=38, fg_color="#2980b9", command=self._start_forensic
        ).pack(anchor="w")

        self.forensic_log = ctk.CTkTextbox(f, height=360, font=ctk.CTkFont(family="Consolas", size=13))
        self.forensic_log.pack(fill="both", expand=True, pady=14)
        self.forensic_log.insert("0.0", "[*] Forensic mode ready (offline).\n")
        self.forensic_log.configure(state="disabled")

        self.frames["forensic"] = f

    def _start_forensic(self) -> None:
        path = filedialog.askdirectory()
        if not path:
            return
        threading.Thread(target=self._run_forensic, args=(path,), daemon=True).start()

    def _run_forensic(self, path: str) -> None:
        def write(msg):
            self.forensic_log.configure(state="normal")
            self.forensic_log.insert("end", msg + "\n")
            self.forensic_log.see("end")
            self.forensic_log.configure(state="disabled")

        write(f"--- Forensic scan: {path} ---")
        report = self.engine.forensic_scan(path)
        write(f"Scanned : {report['scanned']}")
        write(f"Threats : {report['threats']}")
        write(f"Errors  : {report['errors']}")
        for t in report["threat_list"][:50]:
            write(f"  [THREAT] {t['path']}  ({t.get('source')})")
        write("--- Forensic scan complete ---")

    # ---------- Volumes ----------
    def _init_volumes(self) -> None:
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        f.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(f, text="System Volumes", font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", pady=(0, 12)
        )

        self.vol_frame = ctk.CTkScrollableFrame(f, height=400)
        self.vol_frame.pack(fill="both", expand=True)
        self._refresh_volumes()

        ctk.CTkButton(f, text="Refresh", command=self._refresh_volumes, fg_color="gray30").pack(
            anchor="w", pady=10
        )
        self.frames["volumes"] = f

    def _refresh_volumes(self) -> None:
        for w in self.vol_frame.winfo_children():
            w.destroy()
        for p in psutil.disk_partitions():
            try:
                u = psutil.disk_usage(p.mountpoint)
                free = u.free / (1024**3)
                total = u.total / (1024**3)
            except Exception:
                continue
            card = ctk.CTkFrame(self.vol_frame)
            card.pack(fill="x", pady=4, padx=4)
            ctk.CTkLabel(
                card,
                text=f"{p.device}  [{p.fstype}]  {free:.1f}/{total:.1f} GB free",
                font=ctk.CTkFont(size=13, weight="bold"),
            ).pack(side="left", padx=12, pady=10)
            ctk.CTkButton(
                card,
                text="Scan",
                width=90,
                fg_color="#00A86B",
                command=lambda m=p.mountpoint: self._scan_volume(m),
            ).pack(side="right", padx=10)

    def _scan_volume(self, mount: str) -> None:
        self.show_frame("dashboard")
        self.log(f"[!] Full volume scan started: {mount}")
        threading.Thread(target=self._run_volume, args=(mount,), daemon=True).start()

    def _run_volume(self, mount: str) -> None:
        results = self.engine.scan_path(mount)
        threats = sum(1 for r in results if r["status"] == "threat")
        self.log(f"[+] Volume scan done: {mount} — threats: {threats}")

    # ---------- Quarantine ----------
    def _init_quarantine(self) -> None:
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        f.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(f, text="Quarantine", font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", pady=(0, 12)
        )

        self.q_list = ctk.CTkTextbox(f, height=400, font=ctk.CTkFont(family="Consolas", size=13))
        self.q_list.pack(fill="both", expand=True)
        ctk.CTkButton(f, text="Refresh list", command=self._refresh_quarantine).pack(anchor="w", pady=8)
        self._refresh_quarantine()
        self.frames["quarantine"] = f

    def _refresh_quarantine(self) -> None:
        items = self.engine.quarantine.list_items()
        self.q_list.configure(state="normal")
        self.q_list.delete("0.0", "end")
        if not items:
            self.q_list.insert("0.0", "Quarantine is empty.\n")
        else:
            for it in items:
                self.q_list.insert(
                    "end",
                    f"{it['id'][:8]}…  {it.get('filename')}  "
                    f"[{it.get('source')}]  {it.get('quarantined_at', '')}\n",
                )
        self.q_list.configure(state="disabled")

    # ---------- Signatures ----------
    def _init_update(self) -> None:
        f = ctk.CTkFrame(self.container, fg_color="transparent")
        f.grid(row=0, column=0, sticky="nsew")

        ctk.CTkLabel(f, text="Signature Database", font=ctk.CTkFont(size=20, weight="bold")).pack(
            anchor="w", pady=(0, 8)
        )
        ctk.CTkLabel(
            f, text="Local hash signatures for offline detection.", text_color="gray"
        ).pack(anchor="w", pady=(0, 16))

        self.sig_lbl = ctk.CTkLabel(
            f, text=f"Signatures loaded: {self.db.count()}", font=ctk.CTkFont(size=15)
        )
        self.sig_lbl.pack(anchor="w", pady=8)

        ctk.CTkButton(
            f, text="Reload database", height=36, fg_color="#00A86B", command=self._reload_db
        ).pack(anchor="w", pady=10)
        self.frames["update"] = f

    def _reload_db(self) -> None:
        self.db.load()
        self.sig_lbl.configure(text=f"Signatures loaded: {self.db.count()}")
        self.log(f"[+] Signature database reloaded ({self.db.count()} hashes)")
