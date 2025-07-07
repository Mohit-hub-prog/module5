from modules.cve_mapper import map_cves_to_software

kernel = "5.15.0"
software = ["apache", "nginx", "openssl"]
map_cves_to_software(kernel, software)
