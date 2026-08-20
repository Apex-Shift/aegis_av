# AegisAV v2

**Advanced multi-layer security suite (Python core + native-ready architecture).**

AegisAV is an experimental but serious educational / research antivirus framework.  
It combines local signatures, YARA static analysis, cloud threat intelligence and real-time monitoring inside a modern dark GUI.  
The architecture is deliberately designed so a high-performance native layer (Rust) can be added later for interception and speed.

---

## ⚠️ Disclaimer

AegisAV is **not** a replacement for commercial antivirus products.  
It is intended for learning, research, lab environments and forensic analysis.  
Use at your own risk.

---

## Features (v2)

| Layer | Description |
|-------|-------------|
| **Local signatures** | Fast SHA-256 hash database |
| **YARA** | Static pattern matching (default rules included) |
| **Cloud** | MalwareBazaar + VirusTotal |
| **Real-Time Protection** | Monitors Downloads (or any folder) via `watchfiles` |
| **Quarantine** | AES-encrypted isolation + restore |
| **Forensic Mode** | Offline, read-only scan (no cloud, no quarantine) |
| **Volume scan** | Full partition scanning |
| **Native-ready** | Clear path for a Rust interceptor / fast hasher |

---

## Quick Start

```bash
pip install -r requirements.txt

# Optional: VirusTotal key
echo "VIRUSTOTAL_API_KEY=your_key" > .env

python main.py
```

---

## Project Layout

```
AegisAV/
├── main.py
├── requirements.txt
├── src/
│   ├── core/engine.py          # Multi-layer scan engine
│   ├── detection/
│   │   ├── database.py         # Local hash DB
│   │   ├── yara_engine.py
│   │   └── cloud.py            # VT + MalwareBazaar
│   ├── protection/
│   │   ├── quarantine.py       # AES quarantine
│   │   └── realtime.py
│   ├── ui/gui.py
│   └── utils/hashing.py
├── data/
│   ├── yara_rules/
│   ├── signatures/
│   └── quarantine/
├── native/                     # Future Rust layer
└── docs/
```

---

## Forensic Mode

- Pure offline analysis
- No network calls
- No automatic quarantine
- Ideal for incident response / disk imaging analysis

---

## Path to a more serious product

1. Keep the current Python engine for orchestration, YARA, cloud and GUI  
2. Add a **Rust native module** (`native/`) for:
   - Extremely fast hashing
   - File-system filter / process creation callbacks
3. Expose the native functions to Python via PyO3




