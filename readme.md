
<img width="997" height="682" alt="Sans titre" src="https://github.com/user-attachments/assets/8f61abe5-2cac-4502-9c23-d702a3631e34" />

# 🛡️ AegisAV - Advanced Python Security Suite (Experimental)

**AegisAV** is an expert-level, modular antivirus built with Python. It features a multi-layered detection engine combining local hash matching, YARA static rule analysis, and cloud threat intelligence feeds (MalwareBazaar & VirusTotal), wrapped inside a modern, dark-themed GUI inspired by commercial security solutions.

---

## ⚠️ Disclaimer

**DISCLAIMER:** AegisAV is an **experimental, educational project**. It is **not** designed or certified to be used as a primary, enterprise-grade, or standalone security solution. The authors assume no responsibility for any system instability, false positives, data loss, or security breaches resulting from the use of this software. Always rely on certified production-grade antivirus solutions for critical production environments.

---

## 🚀 Key Features

* **Multi-Layered Detection Engine:**
  * **Local Database:** Fast offline hash matching.
  * **YARA Rules:** Advanced static pattern and text-based scanning.
  * **MalwareBazaar & VirusTotal:** Cloud threat intelligence verification.
* **Real-Time Protection (RTP):** Background file-system monitoring to instantly intercept and scan incoming/modified files.
* **Encrypted Quarantine:** Automatically isolates and AES-encrypts detected malicious files to prevent damage.
* **System Volume Manager:** Scans entire partitions or specific custom files/directories on demand.
* **Kaspersky-Style GUI:** Sleek, modern dark-mode interface built with `CustomTkinter`.

---

## 📂 Project Structure

```text
aegis_av/
│
├── data/
│   └── base_virale.json       # Local database with known malware hashes
│
├── src/
│   ├── __init__.py            # Makes the src directory a package
│   ├── moteur.py              # Core scanning logic and file traversal
│   ├── base_donnees.py        # Local signature management and updates
│   ├── api_cloud.py           # Cloud intelligence integration (VirusTotal & MalwareBazaar)
│   └── quarantaine.py         # Secure AES encrypted file isolation
│
├── tests/
│   └── test_scanner.py        # Automated test suites for core modules
│
├── .env                       # Secret environment variables (API Keys)
├── .gitignore                 # Prevents sensitive files and quarantine from being pushed
├── main.py                    # Main application entry point
└── requirements.txt           # Python dependency manifest
```

---

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com
   cd aegis_av
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables:**
   Create a `.env` file at the root directory and add your VirusTotal API key:
   ```env
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

4. **Run the application:**
   ```bash
   python main.py
   ```

---

## 🤝 Contributing

Contributions are welcome! Since **AegisAV** is an educational and experimental project, feel free to open an issue or submit a pull request to add new features (e.g., custom YARA rules, performance optimizations, or GUI enhancements).
