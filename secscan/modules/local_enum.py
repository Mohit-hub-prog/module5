#!/usr/bin/env python3

#Auther: @shivshubh

import subprocess
import os
import getpass
import shutil
import platform
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# Colors
RED = '\033[1;31m'
YELLOW = '\033[0;33m'
GREEN = '\033[1;32m'
RESET = '\033[00m'
ORANGE = '\033[38;5;166m'

LOG_FILE = "enum_report.txt"

def banner():
    print(Fore.RED + Style.BRIGHT + r"""
        [ Automated Local Enumeration Scanner ]
              Ceated by: Shubham Bane
    """ + Style.RESET_ALL)

def write_log(output):
    with open(LOG_FILE, 'a') as f:
        f.write(output + "\n")

def print_and_log(text, color=RESET):
    print(f"{color}{text}{RESET}")
    write_log(text)

def header(title):
    sep = "=" * 68
    print_and_log(sep, YELLOW)
    print_and_log(title, ORANGE)
    print_and_log(sep, YELLOW)

def run(cmd_desc, cmd):
    print_and_log(f"[+] {cmd_desc}", GREEN)
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        output = "[!] Command failed or not available."
    print_and_log(output.strip())
    print_and_log("")  # newline

def is_root():
    return os.geteuid() == 0

# -----------------------------------
# Sections
# -----------------------------------

def system_info():
    header("Basic System Information")
    run("Kernel Version", "uname -a")
    run("Hostname", "hostname")
    run("Current User", "whoami")
    run("User ID Info", "id")
    run("Architecture", "getconf LONG_BIT")
    run("DNS Servers", "awk '/^nameserver/ { print $2 }' /etc/resolv.conf")
    run("Environment PATH", "echo $PATH")

def version_info():
    header("Language and Compiler Versions")
    binaries = {
        "GCC Version": "gcc --version | head -n 1",
        "MySQL Version": "mysql --version",
        "Perl Version": "perl -v | grep version",
        "Ruby Version": "ruby --version",
        "Python3 Version": "python3 --version",
        "Python Version": "python --version"
    }
    for desc, cmd in binaries.items():
        if shutil.which(cmd.split()[0]):
            run(desc, cmd)

def network_info():
    header("Networking")
    run("IP Address", "ip -4 addr show | grep inet")
    run("Routing Table", "ip route")
    run("Listening Ports", "ss -tuln")

def user_info():
    header("Users and Logins")
    run("Users (non-system)", "awk -F: '$3 >= 1000 { print $1 }' /etc/passwd")
    run("Logged In Users", "w")
    run("Sudo Privileges (if any)", "sudo -l")

def filesystem_info():
    header("File System Permissions")
    run("Mounted Filesystems", "cat /etc/fstab")
    run("Home Directory Content", "ls -alh /home/")
    run("SUID Files", "find / -perm -4000 -type f")

def shadow_info():
    header("Shadow File Dump (if root)")
    if is_root():
        run("Dumping Shadow File", "cut -d ':' -f1-2 /etc/shadow | grep -vE '\\*|!'")
    else:
        print_and_log("[!] You are not root. Shadow file requires root access.", RED)

def cron_and_services():
    header("Scheduled Jobs and Services")
    run("Crontab Entries", "cat /etc/crontab")
    run("Service Status", "service --status-all")

def security_info():
    header("Firewall Rules (iptables)")
    run("iptables Rules", "iptables -L -n -v")
    header("ARP Table")
    run("ARP Table", "ip neigh show")

# -----------------------------------
# Main
# -----------------------------------

def run_enum():
    open(LOG_FILE, 'w').close()  # Clear previous logs
    print_and_log(f"[+] Starting enumeration at {datetime.now()}\n", GREEN)
    
    banner()
    system_info()
    version_info()
    network_info()
    user_info()
    filesystem_info()
    shadow_info()
    cron_and_services()
    security_info()

    print_and_log(f"[✔] Enumeration Complete. Output saved to enum_report.txt", GREEN)

if __name__ == "__main__":
    import shutil
    run_enum()
