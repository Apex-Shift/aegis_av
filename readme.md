# AegisAV - Advanced Python Security Suite (Experimental)

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

## 🛠️ Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/your-username/aegis_av.git](https://github.com/your-username/aegis_av.git)
   cd aegis_av


## Install dependencies:

Bash


pip install -r requirements.txt
Configure environment variables:
Create a .env file at the root directory and add your VirusTotal API key:

 


VIRUSTOTAL_API_KEY=your_api_key_here
Run the application:

Bash


python main.py