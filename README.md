# SECScan — Linux Security Misconfiguration & CVE Scanner

SECScan is a modular security auditing tool for Linux systems, designed to help ethical hackers and security analysts identify:

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
