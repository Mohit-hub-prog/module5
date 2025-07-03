import os

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

def find_suid_binaries():
    suid_files = []
    for root, dirs, files in os.walk("/", topdown=True):
        # Avoid permission issues
        dirs[:] = [d for d in dirs if not d.startswith("proc") and not d.startswith("sys") and not d.startswith("dev")]
        for name in files:
            try:
                full_path = os.path.join(root, name)
                if os.path.exists(full_path) and os.stat(full_path).st_mode & 0o4000:
                    suid_files.append(full_path)
            except Exception:
                continue
    return suid_files

def scan_for_misconfigs():
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

    try:
        suid_files = find_suid_binaries()
    except Exception as e:
        print(f"{RED}[!] Error finding SUID binaries: {e}{RESET}")
        return []

    results = []
    for path in suid_files:
        try:
            binary = os.path.basename(path)
            if binary in risky_patterns:
                desc, cve = risky_patterns[binary]
                print(f"{RED}[RISKY] {path} - {desc} ({cve}){RESET}")
                results.append({
                    "path": path,
                    "risky": True,
                    "description": desc,
                    "cve": cve
                })
            else:
                print(f"{GREEN}[SAFE]  {path} - No known risk{RESET}")
                results.append({
                    "path": path,
                    "risky": False,
                    "description": "No known risk",
                    "cve": "-"
                })
        except Exception as e:
            print(f"{YELLOW}[!] Error analyzing binary '{path}': {e}{RESET}")
            continue
    return results

# Run the scan
if __name__ == "__main__":
    print(f"{YELLOW}[*] Scanning for SUID binaries and misconfigurations...{RESET}")
    scan_for_misconfigs()
