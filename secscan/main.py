# main.py

import argparse
import sys
import re
from modules import system_info, local_enum, suid_scanner, cve_mapper, remote_scans

# ------------------------- Argument Parser -------------------------

parser = argparse.ArgumentParser(description='SECScan: Linux Security Misconfiguration & CVE Scanner')
parser.add_argument('--sysinfo', action='store_true', help='Collect basic system information')
parser.add_argument('--enum', action='store_true', help='Run local enumeration checks')
parser.add_argument('--suid', action='store_true', help='Run SUID misconfiguration scanner')
parser.add_argument('--cve', action='store_true', help='Run CVE & OWASP mapping (requires nvdcve JSON)')
parser.add_argument('--remote', nargs='?', const='127.0.0.1', help='Run remote port scan (default: 127.0.0.1)')
parser.add_argument('--all', action='store_true', help='Run all available modules')
parser.add_argument('--output', type=str, help='Save findings to an output report file (e.g., output.html)')


def banner():
    print("\033[1;32m" + r"""
   _____  ______   _____  ______  _____   _____  _______ __     __
  / ____||  ____| / ____||  ____||  __ \ |_   _||__   __|\ \   / /
 | (___  | |__   | |     | |___  | |__) |  | |     | |    \ \_/ / 
  \___ \ |  __|  | |     |  ___| |  _  /   | |     | |     \   /  
  ____) || |____ | |____ | |____ | | \ \  _| |_    | |      | |   
 |_____/ |______| \_____||______||_|  \_\|_____|   |_|      |_|   
                                                                                         
                  Linux Security Misconfiguration & CVE Scanner
                            Creaters: Alex
                                      Jyoti Chandrika
                                      Mohit 
                                      Shubham Bane
    """ + "\033[0m")
def parse_args():
    return parser.parse_args()


# -------------------- Smart Software Detection ----------------------

def extract_software_from_enum(enum_data):
    known_patterns = {
        'apache': r'(apache2|httpd)',
        'nginx': r'nginx',
        'mysql': r'mysql|mariadb',
        'openssl': r'openssl',
        'sshd': r'openssh|sshd',
        'postgres': r'postgresql',
        'ftp': r'vsftpd|proftpd|pure-ftpd',
        'docker': r'docker',
        'cron': r'cron|crond',
        'php': r'php',
    }

    enum_text = ""
    if isinstance(enum_data, dict):
        for v in enum_data.values():
            enum_text += str(v).lower()

    found = []
    for name, pattern in known_patterns.items():
        if re.search(pattern, enum_text):
            found.append(name)

    return list(set(found))


# ------------------------ Run All Modules ---------------------------

def run_all_modules(remote_host='127.0.0.1'):
    results = {}

    print("\n[+] Collecting System Info...")
    sysinfo = system_info.get_system_info()
    system_info.display_info(sysinfo)
    results['system'] = sysinfo

    print("\n[+] Running Local Enumeration...")
    enum_data = local_enum.run_enum()
    results['local_enum'] = enum_data

    print("\n[+] Running SUID Scanner...")
    results['suid'] = suid_scanner.scan_suid()

    print("\n[+] Running CVE & OWASP Mapping...")
    kernel = sysinfo.get("Kernel", "unknown")
    software_list = extract_software_from_enum(enum_data)
    results['cve'] = cve_mapper.map_cves_to_software(kernel, software_list)

    return results


# ---------------------------- Main ----------------------------------

def main():
    banner()
    args = parse_args()

    # Custom help if only --remote is passed without actual target
    if args.remote == '127.0.0.1' and sum(bool(v) for v in vars(args).values()) == 1:
        print("\n[!] Missing remote target IP.")
        print("Usage Examples for python main.py --remote Target_IP\n")
        print("Example:")
        print("  python main.py --remote 192.168.1.1")
        print("  python main.py --remote 10.0.0.5 --output result.html\n")
        sys.exit(1)

    # Show help if no arguments at all
    if not any(vars(args).values()):
        print("\n[!] No options provided.\n")
        parser.print_help()
        sys.exit(1)

    results = {}
    sysinfo_data = {}
    enum_data = {}

    if args.all:
        results = run_all_modules()
    else:
        if args.sysinfo:
            print("\n[+] Collecting System Info...")
            sysinfo_data = system_info.get_system_info()
            system_info.display_info(sysinfo_data)
            results['system'] = sysinfo_data

        if args.enum:
            print("\n[+] Running Local Enumeration...")
            enum_data = local_enum.run_enum()
            results['local_enum'] = enum_data

        if args.suid:
            print("\n[+] Running SUID Misconfiguration Scan...")
            results['suid'] = suid_scanner.scan_suid()

        if args.cve:
            print("\n[+] Running CVE & OWASP Mapping...")

            if not sysinfo_data:
                sysinfo_data = system_info.get_system_info()
            if not enum_data:
                enum_data = local_enum.run_enum()

            kernel = sysinfo_data.get("Kernel", "unknown")
            software_list = extract_software_from_enum(enum_data)
            results['cve'] = cve_mapper.map_cves_to_software(kernel, software_list)

        if args.remote is not None:
            remote_ip = args.remote.strip()
            if not remote_ip:
                print("\n[!] Remote IP is missing or invalid.\n")
                parser.print_help()
                sys.exit(1)
            print(f"\n[+] Running Remote Scanner on {remote_ip}...")
            results['remote'] = remote_scans.scan_remote_host()

    # ------------------- Save to Output File ---------------------------

    if args.output:
        with open(args.output, 'w') as f:
            f.write("<html><head><title>SECScan Report</title></head><body>")
            f.write("<h1>SECScan Security Report</h1>")
            for section, data in results.items():
                f.write(f"<h2>{section.upper()}</h2><ul>")
                if isinstance(data, list):
                    for item in data:
                        f.write(f"<li>{item}</li>")
                elif isinstance(data, dict):
                    for k, v in data.items():
                        f.write(f"<li><b>{k}</b>: {v}</li>")
                else:
                    f.write(f"<li>{data}</li>")
                f.write("</ul>")
            f.write("</body></html>")
        print(f"\n[✔] Report saved to {args.output}")


if __name__ == "__main__":
    main()
