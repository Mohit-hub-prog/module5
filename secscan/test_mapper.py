from modules import cve_mapper

kernel = "5.8.0"
software = ["apache 2.4.29", "openssl 1.0.1", "pkexec 0.105"]

# Run the mapping
results = cve_mapper.map_cves_to_software(kernel, software)

print(f"[+] {len(results)} high severity CVEs saved to 'cve_results.txt'")
