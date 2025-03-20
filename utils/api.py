from modules.reconnaissance import run_nmap_scan

def scan_network(target, output_file="scan_results.json"):
    run_nmap_scan(target, output_file)