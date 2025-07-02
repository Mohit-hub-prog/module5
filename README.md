🔐 SecScan – Linux Vulnerability & Privilege Escalation Scanner
A modular, automation-based tool built to assist ethical hackers, penetration testers, and security analysts in identifying local misconfigurations, SUID issues, and CVE-based vulnerabilities on Linux systems (both local and remote) — without performing exploitation.


⚙️ Features
✅ Automated local privilege escalation checks (LinEnum-style)

✅ SUID/SGID misconfiguration scanner

✅ CVE & OWASP Top 10 vulnerability mapping (kernel + services)

✅ Optional remote service discovery & CVE detection

✅ HTML/JSON/TXT report with:

CVE IDs

OWASP category

Fix instructions

Prevention best practices

📸 Example Output
Report includes:

Local Findings (cron jobs, secrets, env misconfigs)

SUID Misconfigurations → CVEs

Remote Ports/Services → Version → CVEs

Fix + Prevention Guidance

Output: report.html

🚀 Installation
Clone the repo:

bash
Copy
Edit
git clone https://github.com/yourname/secscan.git
cd secscan
pip install -r requirements.txt
chmod +x secscan.py
🧪 Usage
bash
Copy
Edit
./secscan.py [options]
Option	Description
--all	Run full scan (local enum + suid + CVE map)
--enum	Only run local privilege enumeration
--suid	Only run SUID misconfiguration checks
--cve	Only CVE & OWASP mapping (kernel + services)
--remote <IP>	Include remote port/service CVE detection
--output <filename>	Save output as HTML (e.g., report.html)
-h, --help	Show CLI help

🧪 Example:

bash
Copy
Edit
./secscan.py --all --output fullscan.html
./secscan.py --suid --output suid.html
./secscan.py --all --remote 192.168.1.10 --output report.html
🧭 Scan Flow
plaintext
Copy
Edit
[1] System Info
       ↓
[2] Local Enum → cron, files, secrets
       ↓
[3] SUID Scanner → risky binaries → CVEs
       ↓
[4] CVE & OWASP Mapping → kernel, packages
       ↓
[5] Remote Scan (optional) → services + CVEs
       ↓
[6] HTML Report → Findings + Fixes + Prevention
