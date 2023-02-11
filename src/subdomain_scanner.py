from collections.abc import Collection
from concurrent.futures import ThreadPoolExecutor
from itertools import product
from reconlib import CRTShAPI, HackerTargetAPI, VirusTotalAPI


class SubdomainScanner:
    def __init__(
            self, 
            domains: Collection[str], 
            output_file: str, 
            threads: int, 
            virustotal_api_key: str = None
        ):
        self.domains = domains
        self.output_file = output_file
        self.threads = threads
        self.observers = []
        self.virustotal_api_key = virustotal_api_key
        self.apis = [
            CRTShAPI(), 
            HackerTargetAPI(), 
            (VirusTotalAPI(api_key=self.virustotal_api_key) if self.virustotal_api_key else VirusTotalAPI())
        ]
        self.domain_api_products = list(product(self.domains, self.apis))

    def attach(self, observer):
        self.observers.append(observer)

    def notify(self, result):
        for observer in self.observers:
            observer.update(result)

    def scan_url(self, product) -> set[str]:
        return product[1].fetch_subdomains(target=product[0])

    def scan(self):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                for result in executor.map(self.scan_url, self.domain_api_products):
                    self.notify(result)
            except KeyboardInterrupt:
                print("\n[-] Scan ended by user input")

        for observer in self.observers:
            observer.end_output()
