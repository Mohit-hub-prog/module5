# Linux Security Misconfiguration & CVE Scanner

This is a modular security auditing tool for Linux systems, designed to help ethical hackers and security analysts identify:

- Local misconfigurations
- SUID permission issues
- Known CVEs based on installed software and kernel version
- OWASP Top 10 categories for detected vulnerabilities

---

## 🔧 Features

- ✅ Automated Local Enumeration (system info, cron, users, permissions)
- ✅ SUID Misconfiguration Scanner
- ✅ CVE Mapping from NVD JSON Feed
- ✅ OWASP Top 10 Classification
- ✅ HTML Report Generation
- ✅ Simple CLI Interface for Custom Scans

---

## 📦 Installation

Clone the repository and set up dependencies:

```bash
git clone https://github.com/Mohit-hub-prog/module5/
cd module5
cd secscan
pip install --upgrade pip --break-system-packages
pip install nvdlib --break-system-packages
````

Make sure you download the latest CVE data JSON (e.g., nvdcve-1.1-recent.json) from the [NVD feed](https://nvd.nist.gov/vuln/data-feeds) and place it inside the secscan/data/ directory.

---

## 🚀 Usage

Basic usage:

```bash
python main.py --all
```

Optional flags:

| Flag     | Description                                |
| -------- | ------------------------------------------ |
| --enum   | Run local enumeration checks               |
| --suid   | Scan for SUID misconfigurations            |
| --cve    | Run CVE & OWASP mapping (test mode)        |
| --all    | Run all modules                            |
| --output | Save HTML report (e.g., --output out.html) |

---

## 🤝 Authors

* Developed by: @shivshubh, @Mohit-hub-prog, @JyothichandrikaGanpisetti and @SecuredByAlex
* Language: Python 3.x
* Dependencies: colorama, nvdlib, psutil, platform, socket, uuid

---

