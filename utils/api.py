from modules.reconnaissance import Reconnaissance

class PentestAPI:
    def __init__(self):
        self.recon = Reconnaissance()

    def scan_network(self, target, output_file="scan_results.json"):
        return self.recon.run_nmap_scan(target, output_file)