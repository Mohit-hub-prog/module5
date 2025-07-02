from modules import suid_scanner
import os
import json

def main():
    print("\n==========================")
    print("  SUID Misconfig Scanner")
    print("==========================\n")

    results = suid_scanner.scan_for_misconfigs()

    risky = [r for r in results if r["risky"]]
    safe = [r for r in results if not r["risky"]]

    print("[+] Scan Complete.")
    print(f"[+] Total SUIDs found: {len(results)}")
    print(f"[!] Risky SUIDs detected: {len(risky)}\n")

    for entry in risky:
        print(f"[!] {entry['path']}")
        print(f"    ↳ {entry['description']}")
        print(f"    ↳ CVE: {entry['cve']}\n")

    output_path = "reports/suid_scan_results.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"[+] Results saved to {output_path}")

if __name__ == "__main__":
    main()

