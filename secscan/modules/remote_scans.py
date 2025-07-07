import argparse
import subprocess
import socket
from colorama import Fore, Style, init
import sys

init(autoreset=True)

def banner():
    print(Fore.RED + Style.BRIGHT + r"""
    
         [ Remote IP Enumeration Tool ]
          Created by: Jyoti Chandrika
    """ + Style.RESET_ALL)

# --------------------------------------------
# Known vulnerable services
# --------------------------------------------
known_services = {
    'Apache': {
        'aliases': ['apache', 'apache httpd'],
        'cve': 'CVE-2021-41773',
        'owasp': 'A05: Security Misconfiguration'
    },
    'OpenSSH': {
        'aliases': ['openssh', 'sshd'],
        'cve': 'CVE-2018-15473',
        'owasp': 'A01: Broken Access Control'
    },
    'MySQL': {
        'aliases': ['mysql'],
        'cve': 'CVE-2020-25794',
        'owasp': 'A06: Vulnerable and Outdated Components'
    },
    'POP3': {
        'aliases': ['pop3', 'qpopper', 'dovecot'],
        'cve': 'CVE-2015-1430',
        'owasp': 'A06: Vulnerable and Outdated Components'
    },
    'SMTP': {
        'aliases': ['smtp', 'postfix', 'exim', 'sendmail'],
        'cve': 'CVE-2019-15846',
        'owasp': 'A06: Vulnerable and Outdated Components'
    },
    'FTP': {
        'aliases': ['ftp', 'vsftpd'],
        'cve': 'CVE-2011-2523',
        'owasp': 'A05: Security Misconfiguration'
    },
    'MSRPC': {
        'aliases': ['msrpc', 'microsoft rpc'],
        'cve': 'CVE-2021-31166',
        'owasp': 'A05: Security Misconfiguration'
    },
    'RealServer': {
        'aliases': ['realserver', 'real audio server'],
        'cve': 'CVE-2007-0909',
        'owasp': 'A06: Vulnerable and Outdated Components'
    },
    'SMB': {
        'aliases': ['smb', 'samba', 'windows file sharing'],
        'cve': 'CVE-2017-0144',
        'owasp': 'A01: Broken Access Control'
    },
    'RDP': {
        'aliases': ['rdp', 'remote desktop'],
        'cve': 'CVE-2019-0708',
        'owasp': 'A05: Security Misconfiguration'
    }
}

# --------------------------------------------
# Argument parser (global to reuse for help)
# --------------------------------------------
parser = argparse.ArgumentParser(description='Remote Enumeration Tool')
parser.add_argument('--remote', type=str, help='Target IP address')
parser.add_argument('--output', type=str, default='remote_report.txt', help='Output report file')

def parse_args():
    return parser.parse_args()

# --------------------------------------------
# Nmap scan
# --------------------------------------------
def scan_ports(ip):
    print(f"[+] Running Nmap scan on {ip} ...")
    try:
        result = subprocess.run(['nmap', '-sV', '-T4', '-Pn', ip],
                                capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"[!] Nmap scan failed: {e}"

# --------------------------------------------
# Banner grabbing
# --------------------------------------------
def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))

            if port in [80, 443]:
                s.sendall(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 110:
                s.sendall(b'CAPA\r\n')
            elif port == 25:
                s.sendall(b'EHLO test\r\n')

            banner = s.recv(1024).decode(errors='ignore')
            return banner.strip()
    except Exception:
        return "No banner retrieved"

# --------------------------------------------
# Map service output to CVEs
# --------------------------------------------
def map_service_to_cve(text_output):
    findings = []
    lower_output = text_output.lower()
    for service, data in known_services.items():
        for alias in data['aliases']:
            if alias in lower_output:
                findings.append({
                    'service': service,
                    'cve': data['cve'],
                    'owasp': data['owasp']
                })
                break
    return findings

# --------------------------------------------
# Format and print/save results
# --------------------------------------------
def format_results(ip, nmap_out, banners, vulns):
    lines = [f"\n==== Remote Enumeration for {ip} ====\n"]

    lines.append("\n[+] Port Scan Result:")
    lines.append(nmap_out.strip())

    lines.append("\n[+] Banner Grabbing Results:")
    for port, banner in banners.items():
        lines.append(f"  Port {port}: {banner}")

    lines.append("\n[+] Mapped Vulnerabilities:")
    if vulns:
        for v in vulns:
            lines.append(f"  Service: {v['service']}")
            lines.append(f"    CVE: {v['cve']}")
            lines.append(f"    OWASP: {v['owasp']}")
    else:
        lines.append("  No known vulnerabilities matched.")

    return '\n'.join(lines)

# --------------------------------------------
# Main logic
# --------------------------------------------
def scan_remote_host():
    banner()
    args = parse_args()

    if not args.remote:
        print(Fore.RED + "[!] No target IP provided.\n")
        parser.print_help()
        sys.exit(1)

    ip = args.remote
    nmap_output = scan_ports(ip)

    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 3306, 135, 445, 3389, 7070]
    banners = {}
    for port in common_ports:
        print(Fore.YELLOW + f"[*] Grabbing banner from port {port}...")
        banners[port] = grab_banner(ip, port)

    combined_text = nmap_output + "\n" + "\n".join(banners.values())
    matched_vulns = map_service_to_cve(combined_text)

    report_text = format_results(ip, nmap_output, banners, matched_vulns)
    print(Fore.CYAN + report_text)

    with open(args.output, 'w') as f:
        f.write(report_text)
        print(Fore.GREEN + f"\n[+] Remote enumeration results saved to: {args.output}")

if __name__ == "__main__":
    scan_remote_host()
