# modules/cve_mapper.py
import nvdlib
import os

def load_cve_data(json_path):
    if not os.path.exists(json_path):
        raise FileNotFoundError(f"CVE data file not found at: {json_path}")
    print(f"[+] Loading CVE data from: {json_path}")
    return nvdlib.loadJSON(json_path)

def classify_owasp(description):
    description = description.lower()
    if any(x in description for x in ['sql injection', 'command injection', 'log4j']):
        return "A03: Injection"
    elif 'auth' in description or 'bypass' in description:
        return "A01: Broken Access Control"
    elif 'memory leak' in description or 'openssl' in description:
        return "A02: Cryptographic Failures"
    elif 'csrf' in description:
        return "A06: Vulnerable & Outdated Components"
    elif 'ssrf' in description:
        return "A10: SSRF"
    elif 'logging' in description:
        return "A09: Logging & Monitoring Failures"
    elif 'misconfig' in description or 'default' in description:
        return "A05: Security Misconfiguration"
    else:
        return "Unclassified"

def add_manual_vuln(cves):
    manual_entry = type('ManualCVE', (), {})()
    manual_entry.id = "CVE-9999-0001"
    manual_entry.score = 9.0
    manual_entry.descriptions = [type('Desc', (), {"value": "Test Injection vulnerability in apache 2.4.29 allows remote code execution via special request."})()]
    manual_entry.published = "2025-07-01 12:00:00"
    manual_entry.lastModified = "2025-07-01 12:00:00"
    manual_entry.sourceIdentifier = "ManualEntry"
    cves.append(manual_entry)
    return cves

def map_cves_to_software(kernel_version, software_list, json_path='./data/nvdcve-1.1-recent.json', output_txt='cve_results.txt'):
    try:
        cves = load_cve_data(json_path)
    except Exception as e:
        print(f"[!] Error loading CVE data: {e}")
        cves = []

    cves = add_manual_vuln(cves)

    results = []
    kernel_version = kernel_version.lower().strip()
    software_list = [s.lower() for s in software_list]

    for cve in cves:
        if not hasattr(cve, 'descriptions') or not cve.descriptions:
            continue

        description = cve.descriptions[0].value.lower()
        matched = False

        # Check kernel version in description
        if 'linux' in description and kernel_version in description:
            matched = True

        # Check software names and versions
        for sw in software_list:
            if sw in description:
                matched = True
                break

        if matched:
            severity = getattr(cve, 'score', 0.0)
            if severity and float(severity) >= 7.0:
                entry = {
                    'cve_id': cve.id,
                    'severity': severity,
                    'description': description,
                    'published': str(cve.published),
                    'lastModified': str(cve.lastModified),
                    'sourceIdentifier': cve.sourceIdentifier,
                    'owasp_category': classify_owasp(description)
                }
                results.append(entry)

    # Write results to output file
    if results:
        with open(output_txt, 'w') as f:
            for v in results:
                f.write(f"CVE ID       : {v['cve_id']}\n")
                f.write(f"Severity     : {v['severity']}\n")
                f.write(f"Published    : {v['published']}\n")
                f.write(f"OWASP        : {v['owasp_category']}\n")
                f.write(f"Description  : {v['description'][:300]}...\n")
                f.write(f"Source       : {v['sourceIdentifier']}\n")
                f.write("-" * 60 + "\n")
        print(f"[+] Output saved to {output_txt}")

    return results
