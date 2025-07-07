import os
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)


def find_suid_binaries():
    suid_files = []
    for root, dirs, files in os.walk("/", topdown=True):
        dirs[:] = [d for d in dirs if d not in ("proc", "sys", "dev", "run", "tmp")]
        for name in files:
            try:
                full_path = os.path.join(root, name)
                if os.path.exists(full_path) and os.stat(full_path).st_mode & 0o4000:
                    suid_files.append(full_path)
            except Exception:
                continue
    return suid_files

def scan_suid(output_file="suid_results.txt"):
    risky_patterns = {
        "pkexec": ("Polkit pkexec privilege escalation", "CVE-2021-4034"),
        "vim": ("Shell escape via :!sh", "Known misconfiguration"),
        "nmap": ("Interactive shell via --interactive", "Known misconfiguration"),
        "find": ("Shell via -exec command", "Known misconfiguration"),
        "perl": ("Can invoke shell via -e exec", "Known misconfiguration"),
        "python": ("Can spawn shell with os.system", "Known misconfiguration"),
        "bash": ("Direct shell access", "Known misconfiguration"),
        "cp": ("Can overwrite critical files", "Known misconfiguration"),
        "less": ("Shell escape via !", "Known misconfiguration"),
        "man": ("Shell escape via manpath", "Known misconfiguration"),
        "awk": ("Execute shell via system()", "Known misconfiguration"),
        "tar": ("Shell via --checkpoint-action", "Known misconfiguration"),
        "env": ("Execute arbitrary command", "Known misconfiguration"),
        "lua": ("os.execute shell invocation", "Known misconfiguration"),
        "node": ("Shell via child_process", "Known misconfiguration"),
        "ftp": ("Shell escape via !", "Known misconfiguration"),
        "docker": ("Possible container escape", "Depends on setup")
    }

    suid_files = find_suid_binaries()
    results = []

    with open(output_file, "w") as f:
        header = "Scanning for SUID binaries and potential misconfigurations...\n"
        print(Fore.CYAN + Style.BRIGHT + header)
        f.write(header + "\n")

        for path in suid_files:
            binary = os.path.basename(path)
            if binary in risky_patterns:
                desc, cve = risky_patterns[binary]
                result = {
                    "path": path,
                    "risky": True,
                    "description": desc,
                    "cve": cve
                }
                color = Fore.RED + Style.BRIGHT
                status = "RISKY"
            else:
                result = {
                    "path": path,
                    "risky": False,
                    "description": "No known risk",
                    "cve": "-"
                }
                color = Fore.GREEN
                status = "OK"

            results.append(result)

            # Console output
            print(f"{color}[{status}] {path}")
            print(f"{Style.DIM}    Description: {result['description']}")
            print(f"{Style.DIM}    CVE: {result['cve']}\n")

            # File output (no colors)
            f.write(f"[{status}] {path}\n")
            f.write(f"    Description: {result['description']}\n")
            f.write(f"    CVE: {result['cve']}\n\n")

    print(Fore.GREEN + Style.BRIGHT + f"[✔] Enumeration Complete. Output saved to {output_file}")
    return results

if __name__ == "__main__":
    scan_suid()
