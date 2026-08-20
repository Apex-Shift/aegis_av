# Native Layer (Rust) — Roadmap

This folder is the future home of the high-performance / low-level component of AegisAV.

## Goals

| Capability | Technology | Status |
|------------|------------|--------|
| Ultra-fast hashing of large files | Rust (`blake3` / `sha2`) | Planned |
| Real-time process & file interception | Rust + OS hooks / minifilter (Windows) or fanotify/inotify (Linux) | Planned |
| Memory scanning | Rust | Planned |
| Python bindings | `PyO3` | Planned |

## Why a native layer?

Python is excellent for:
- Orchestration
- YARA
- Cloud APIs
- GUI
- Forensic reporting

It is **not** ideal for:
- Kernel-level interception
- Scanning terabytes at maximum speed
- Inline blocking of process creation

## Suggested architecture

```
┌─────────────────────────────────────┐
│           AegisAV Python            │
│  (GUI, YARA, Cloud, Quarantine,     │
│   Forensic mode, Signature DB)      │
└──────────────┬──────────────────────┘
               │  PyO3 / CFFI
┌──────────────▼──────────────────────┐
│         aegis_native (Rust)         │
│  - Fast hash                        │
│  - File system filter               │
│  - Process creation callback        │
└─────────────────────────────────────┘
```

## Getting started (when ready)

```bash
cd native
cargo new aegis_native --lib
# add pyo3, sha2, etc.
```

This design keeps the detection logic and user experience in Python while allowing a serious performance and interception layer later.
