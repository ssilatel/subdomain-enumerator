from collections.abc import Collection
from concurrent.futures import ThreadPoolExecutor
from reconlib import crtsh, hackertarget

class SubdomainScanner:
    def __init__(
            self,
            url: Collection[str],
            output_file: str,
            threads: int
        ):
        self.url = url
        self.output_file = output_file
        self.threads = threads
        self.observers = []

    def attach(self, observer):
        self.observers.append(observer)

    def notify(self, result):
        for observer in self.observers:
            observer.update(result)

    def scan_url(self, url):
        found_domains = []
        crtsh_info = crtsh.API(target=url)
        crtsh_info.fetch()
        found_domains.append(crtsh_info.found_domains)

        hackertarget_info = hackertarget.API(target=url)
        hackertarget_info.hostsearch()
        found_domains.append(hackertarget_info.found_domains)

        return found_domains

    def scan(self):
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            try:
                for result in executor.map(self.scan_url, self.url):
                    self.notify(result)
            except KeyboardInterrupt:
                print("\n[-] Scan ended by user input")