# System Information Script
# Author: @shivshubh

import platform
import socket
import uuid
import psutil
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def banner():
    print(Fore.RED + Style.BRIGHT + r"""
        [ Basic System information finder ]
              Ceated by: Shubham Bane
    """ + Style.RESET_ALL)

def get_system_info():
    data = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "OS": platform.system(),
        "Hostname": platform.node(),
        "OS_Release": platform.release(),
        "OS_Version": platform.version(),
        "Hardware": platform.machine(),
        "CPU": platform.processor(),
        "Architecture": platform.architecture()[0],
        "Local_IP": socket.gethostbyname(socket.gethostname()),
        "MAC": ':'.join(['{:02x}'.format((uuid.getnode() >> shift) & 0xff)
                         for shift in range(0, 8*6, 8)][::-1]),
        "Memory_GB": round(psutil.virtual_memory().total / (1024**3), 2),
        "Disk": {
            "Total_GB": round(psutil.disk_usage('/').total / (1024**3), 2),
            "Used_GB": round(psutil.disk_usage('/').used / (1024**3), 2),
            "Free_GB": round(psutil.disk_usage('/').free / (1024**3), 2),
            "Usage_Percent": psutil.disk_usage('/').percent
        },
        "Booted_At": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "CPU_Cores": psutil.cpu_count(logical=True),
        "CPU_Load": psutil.cpu_percent(interval=1)
    }
    return data

def display_info(info):

    banner()
    print(Fore.CYAN + "\n--- System Information ---\n" + Style.RESET_ALL)
    for key, val in info.items():
        if isinstance(val, dict):
            print(Fore.YELLOW + f"{key}:" + Style.RESET_ALL)
            for sub_key, sub_val in val.items():
                print(f"  {Fore.GREEN}{sub_key}{Style.RESET_ALL}: {Fore.WHITE}{sub_val}")
        else:
            print(f"{Fore.BLUE}{key}{Style.RESET_ALL}: {Fore.WHITE}{val}")
    print(Fore.CYAN + "\n--------------------------\n" + Style.RESET_ALL)

def save_info(info):
    with open("system_info.txt", "w") as txt:
        for key, val in info.items():
            if isinstance(val, dict):
                txt.write(f"{key}:\n")
                for sub_key, sub_val in val.items():
                    txt.write(f"  {sub_key}: {sub_val}\n")
            else:
                txt.write(f"{key}: {val}\n")

    with open("system_info.json", "w") as js:
        json.dump(info, js, indent=4)

if __name__ == "__main__":
    info = get_system_info()
    display_info(info)
    save_info(info)
