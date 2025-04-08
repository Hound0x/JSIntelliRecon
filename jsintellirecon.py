import argparse
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import json
from termcolor import colored


class JSIntelliRecon:
    def __init__(self, url, output, deep=False):
        self.url = url.rstrip('/')
        self.output = output
        self.deep = deep
        self.js_files = set()
        self.results = []
        self.sensitive_keywords = ['auth', 'admin', 'debug', 'config', 'reset', 'token', 'login']

    def fetch_html(self, target_url):
        try:
            response = requests.get(target_url, timeout=10)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            print(colored(f"[!] Error fetching {target_url}: {e}", "red"))
        return ""

    def extract_js_links(self, html):
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src')
            if src:
                full_url = urljoin(self.url, src)
                self.js_files.add(full_url)
            elif script.string:
                inline_js = script.string
                self.analyze_js(inline_js, self.url + ' (inline)')

    def fetch_js(self, js_url):
        try:
            response = requests.get(js_url, timeout=10)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            print(colored(f"[!] Error fetching JS file {js_url}: {e}", "red"))
        return ""

    def tag_sensitive(self, item):
        tags = [kw for kw in self.sensitive_keywords if kw in item.lower()]
        return f" [TAG: {', '.join(tags)}]" if tags else ""

    def analyze_js(self, js_code, js_url):
        endpoints = list(set(re.findall(r'[\"\']((?:https?:)?\/\/[^\"\']+)[\"\']', js_code)))
        secrets = re.findall(r'(?:api[_-]?key|token|secret|password)[\"\']?\s*[:=]\s*[\"\']([^\"\']+)[\"\']', js_code, re.IGNORECASE)
        versions = list(set(re.findall(r'(jquery|react|angular)[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)', js_code, re.IGNORECASE)))
        internal_paths = list(set(re.findall(r'/\w+/\w+\.(?:php|aspx|jsp|json|html)', js_code)))
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', js_code)

        if endpoints or secrets or versions or internal_paths or ips:
            print(colored(f"\n[+] Analyzing: {js_url}", "cyan"))
            if endpoints:
                print(colored("[!] API Endpoints:", "yellow"))
                for endpoint in endpoints:
                    tag = self.tag_sensitive(endpoint)
                    print(f"  - {endpoint}{tag}")
            if secrets:
                print(colored("[!] Possible Secrets:", "red"))
                for secret in secrets:
                    print(f"  - {secret}")
            if versions:
                print(colored("[!] Detected Library Versions:", "magenta"))
                for lib, ver in versions:
                    print(f"  - {lib} {ver}")
            if internal_paths:
                print(colored("[!] Internal Paths:", "green"))
                for path in internal_paths:
                    tag = self.tag_sensitive(path)
                    print(f"  - {path}{tag}")
            if ips:
                print(colored("[!] Internal IPs:", "red"))
                for ip in ips:
                    print(f"  - {ip}")

        findings = {
            'url': js_url,
            'endpoints': endpoints,
            'secrets': secrets,
            'versions': versions,
            'internal_paths': internal_paths,
            'ips': ips
        }
        self.results.append(findings)

    def run(self):
        print(colored(f"[*] Scanning {self.url}...", "cyan"))
        html = self.fetch_html(self.url)
        self.extract_js_links(html)

        if self.deep:
            soup = BeautifulSoup(html, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link['href']
                if urlparse(href).netloc == '' and href.startswith('/'):
                    subpage_url = urljoin(self.url, href)
                    print(colored(f"[*] Crawling subpage: {subpage_url}", "cyan"))
                    sub_html = self.fetch_html(subpage_url)
                    self.extract_js_links(sub_html)

        for js_file in self.js_files:
            js_code = self.fetch_js(js_file)
            if js_code:
                self.analyze_js(js_code, js_file)

        with open(self.output, 'w') as f:
            json.dump(self.results, f, indent=4)

        print(colored(f"\n[+] Done! Results saved to {self.output}", "green"))


def main():
    parser = argparse.ArgumentParser(description='JSIntelliRecon - JavaScript Reconnaissance Tool')
    parser.add_argument('--url', required=True, help='Target URL')
    parser.add_argument('--output', required=True, help='Output file (JSON)')
    parser.add_argument('--deep', action='store_true', help='Enable deep crawling for subpages')
    args = parser.parse_args()

    recon = JSIntelliRecon(args.url, args.output, args.deep)
    recon.run()


if __name__ == '__main__':
    main()
