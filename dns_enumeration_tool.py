#!/usr/bin/env python3
import argparse
import dns.resolver
import socket
import requests
import whois
import ipaddress
import json
import os
import re
import csv
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import sys
from typing import List, Dict, Optional
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('dns_enum.log')
    ]
)
logger = logging.getLogger(__name__)

class DNSEnumerationTool:
    def __init__(self, domain: str, output_dir: str = "dns_results", dns_server: Optional[str] = None, 
                 debug: bool = False, proxy: Optional[str] = None, log_level: str = "INFO"):
        """
        Initialize Yesilho's DJEV DNS Enumeration Tool.

        :param domain: Target domain or URL to enumerate (e.g., exemple.com or https://exemple.com/EN)
        :param output_dir: Directory to save results
        :param dns_server: Custom DNS server (e.g., 8.8.8.8)
        :param debug: Enable debug output for detailed errors
        :param proxy: Proxy for HTTP requests (e.g., http://proxy:port)
        :param log_level: Logging level (INFO, WARNING, ERROR, DEBUG)
        """
        self.raw_input = domain.strip().lower()
        self.domain = self._extract_domain(self.raw_input)
        self.base_domain = self.domain.split('.')[0]
        self.output_dir = output_dir
        self.dns_server = dns_server or "8.8.8.8"
        self.debug = debug
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
        self.results: Dict[str, List[str] | Dict | None] = {
            'a_records': [], 'aaaa_records': [], 'mx_records': [], 'txt_records': [],
            'ns_records': [], 'cname_records': [], 'soa_records': [], 'srv_records': [],
            'caa_records': [], 'ptr_records': [], 'subdomains': [], 'tld_variations': [],
            'whois_info': None, 'ip_ranges': [], 'subdomain_cnames': {}, 'vulnerabilities': []
        }
        self.default_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
            'support', 'cpanel', 'webmail', 'server', 'ns1', 'ns2', 'backup',
            'mx', 'smtp', 'exchange', 'api', 'login', 'portal', 'vpn', 'db'
        ]
        self.default_tlds = [
            'com', 'org', 'net', 'edu', 'gov', 'co', 'io', 'ai', 'biz', 'info',
            'me', 'us', 'uk', 'ca', 'de', 'fr', 'jp', 'cn', 'ru', 'au'
        ]
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_domain = re.sub(r'[^a-zA-Z0-9.-]', '_', self.domain)
        self.output_file = f"{self.output_dir}/{sanitized_domain}_{self.timestamp}"

    def _extract_domain(self, input_str: str) -> str:
        pattern = r'(?:https?://)?([^/]+\.[a-zA-Z]{2,})(?:/.*)?$'
        match = re.match(pattern, input_str)
        if match:
            return match.group(1).lower()
        return input_str

    def resolve_record(self, record_type: str, domain: str = None) -> List[str]:
        domain = domain or self.domain
        try:
            records = []
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(domain, record_type)
            for rdata in answers:
                records.append(str(rdata))
            logger.debug(f"Resolved {record_type} for {domain}: {records}")
            return records
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.resolver.Timeout) as e:
            if self.debug:
                logger.warning(f"{record_type} resolution for {domain} failed: {e}")
            return []

    def enumerate_standard_records(self) -> None:
        record_types = {
            'a_records': 'A', 'aaaa_records': 'AAAA', 'mx_records': 'MX', 'txt_records': 'TXT',
            'ns_records': 'NS', 'cname_records': 'CNAME', 'soa_records': 'SOA', 'srv_records': 'SRV',
            'caa_records': 'CAA', 'ptr_records': 'PTR'
        }
        for key, rtype in record_types.items():
            self.results[key] = self.resolve_record(rtype)

    def enumerate_subdomains(self, wordlist: Optional[List[str]] = None, threads: int = 20) -> None:
        wordlist = wordlist or self.default_subdomains
        logger.info(f"Enumerating subdomains with {threads} threads...")
        def check_subdomain(subdomain: str) -> Optional[tuple[str, Optional[str]]]:
            full_domain = f"{subdomain}.{self.domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                a_records = self.resolve_record('A', full_domain)
                cname_records = self.resolve_record('CNAME', full_domain)
                if a_records or cname_records:
                    return (full_domain, cname_records[0] if cname_records else None)
                return None
            except socket.gaierror:
                return None
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            for future in tqdm(as_completed(futures), total=len(wordlist), desc="Subdomains"):
                result = future.result()
                if result:
                    subdomain, cname = result
                    if subdomain and subdomain not in self.results['subdomains']:
                        self.results['subdomains'].append(subdomain)
                    if cname:
                        self.results['subdomain_cnames'][subdomain] = cname

    def enumerate_tld_variations(self, tld_list: Optional[List[str]] = None, threads: int = 20) -> None:
        tld_list = tld_list or self.default_tlds
        logger.info(f"Enumerating TLD variations for {self.base_domain} with {threads} threads...")
        def check_tld(tld: str) -> Optional[str]:
            full_domain = f"{self.base_domain}.{tld}"
            try:
                ip = socket.gethostbyname(full_domain)
                a_records = self.resolve_record('A', full_domain)
                if a_records:
                    return full_domain
                return None
            except socket.gaierror:
                return None
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(check_tld, tld): tld for tld in tld_list}
            for future in tqdm(as_completed(futures), total=len(tld_list), desc="TLD Variations"):
                result = future.result()
                if result and result not in self.results['tld_variations']:
                    self.results['tld_variations'].append(result)

    def passive_subdomain_enum(self, rate_limit_delay: float = 1.0) -> None:
        logger.info("Performing passive subdomain enumeration...")
        subdomains = set()

        # Source 1: crt.sh
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=10, proxies=self.proxy)
            if response.status_code == 429:
                logger.warning("Rate limit hit on crt.sh. Waiting and retrying...")
                time.sleep(rate_limit_delay)
                response = requests.get(url, timeout=10, proxies=self.proxy)
            data = response.json()
            crt_subdomains = {entry['name_value'].strip().lower() for entry in data}
            subdomains.update(crt_subdomains)
            logger.info(f"Found {len(crt_subdomains)} subdomains via crt.sh")
        except Exception as e:
            logger.error(f"Passive recon via crt.sh failed: {e}")

        # Source 2: HackerTarget (free, no API key)
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            response = requests.get(url, timeout=10, proxies=self.proxy)
            if response.status_code == 429:
                logger.warning("Rate limit hit on HackerTarget. Waiting and retrying...")
                time.sleep(rate_limit_delay)
                response = requests.get(url, timeout=10, proxies=self.proxy)
            if response.status_code == 200:
                lines = response.text.strip().split('\n')
                hacker_subdomains = {line.split(',')[0].strip().lower() for line in lines if line}
                subdomains.update(hacker_subdomains)
                logger.info(f"Found {len(hacker_subdomains)} subdomains via HackerTarget")
            else:
                logger.error(f"HackerTarget returned status {response.status_code}")
        except Exception as e:
            logger.error(f"Passive recon via HackerTarget failed: {e}")

        # Add new subdomains to results
        new_subdomains = [s for s in subdomains if s not in self.results['subdomains']]
        self.results['subdomains'].extend(new_subdomains)
        logger.info(f"Total new subdomains added: {len(new_subdomains)}")

    def reverse_dns_lookup(self, ip: str) -> List[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return [hostname]
        except (socket.herror, socket.gaierror):
            return []

    def enumerate_ip_ranges(self) -> None:
        for a_record in self.results['a_records']:
            try:
                ip = ipaddress.ip_address(a_record)
                if ip.is_private:
                    continue
                network = ipaddress.ip_network(f"{ip}/24", strict=False)
                with ThreadPoolExecutor(max_workers=10) as executor:
                    futures = [executor.submit(self.reverse_dns_lookup, str(ip))
                               for ip in network.hosts()[:10]]
                    for future in as_completed(futures):
                        result = future.result()
                        if result:
                            self.results['ip_ranges'].extend(result)
            except ValueError:
                continue

    def get_whois_info(self) -> None:
        try:
            domain_info = whois.whois(self.domain)
            self.results['whois_info'] = {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date),
                'expiration_date': str(domain_info.expiration_date),
                'name_servers': domain_info.name_servers,
                'registrant': domain_info.registrant_name,
                'organization': domain_info.org
            }
            logger.info("WHOIS information retrieved successfully")
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")

    def check_zone_transfer(self) -> List[str]:
        zone_data = []
        for ns in self.results['ns_records']:
            try:
                ns_ip = socket.gethostbyname(ns.split()[0] if ' ' in ns else ns)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, self.domain))
                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        zone_data.append(f"{name} {rdataset}")
                logger.warning(f"Vulnerability: Open zone transfer detected on {ns}")
                self.results['vulnerabilities'].append(f"Open zone transfer: {ns}")
            except (dns.exception.FormError, dns.query.TransferError, socket.gaierror, ConnectionResetError) as e:
                logger.info(f"Zone transfer failed from {ns}: {e}")
                continue
        return zone_data

    def check_dangling_cnames(self) -> None:
        logger.info("Checking for dangling CNAMEs...")
        for subdomain, cname in self.results['subdomain_cnames'].items():
            try:
                socket.gethostbyname(cname)
            except socket.gaierror:
                logger.warning(f"Vulnerability: Dangling CNAME detected - {subdomain} points to {cname}")
                self.results['vulnerabilities'].append(f"Dangling CNAME: {subdomain} -> {cname}")

    def check_open_resolvers(self) -> None:
        logger.info("Checking for open resolvers...")
        for ns in self.results['ns_records']:
            try:
                ns_ip = socket.gethostbyname(ns.split()[0] if ' ' in ns else ns)
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [ns_ip]
                resolver.resolve("google.com", "A")
                logger.warning(f"Vulnerability: Open resolver detected at {ns}")
                self.results['vulnerabilities'].append(f"Open resolver: {ns}")
            except Exception:
                continue

    def check_ns_misconfig(self) -> None:
        logger.info("Checking for nameserver misconfigurations...")
        ns_records = self.results['ns_records']
        if len(ns_records) < 2:
            logger.warning("Vulnerability: Fewer than 2 nameservers detected (single point of failure)")
            self.results['vulnerabilities'].append("Single nameserver detected")

    def run_full_enumeration(self, threads: int = 20, reverse: bool = False, tld_brute: bool = False,
                            passive: bool = False, vuln_check: bool = False) -> Dict:
        logger.info(f"Starting Yesilho's DJEV DNS Enumeration Tool for {self.domain}")
        self.enumerate_standard_records()
        if passive:
            self.passive_subdomain_enum()
        self.enumerate_subdomains(threads=threads)
        if tld_brute:
            self.enumerate_tld_variations(threads=threads)
        if reverse:
            self.enumerate_ip_ranges()
        self.get_whois_info()
        self.results['zone_transfer'] = self.check_zone_transfer()
        if vuln_check:
            self.check_dangling_cnames()
            self.check_open_resolvers()
            self.check_ns_misconfig()
        self.save_results()
        return self.results

    def save_results(self, format: str = 'json') -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        output_file = f"{self.output_file}.{format}"
        if format == 'csv':
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Type', 'Value'])
                for key, values in self.results.items():
                    if isinstance(values, list):
                        for v in values:
                            writer.writerow([key, v])
                    elif isinstance(values, dict):
                        for sub_key, sub_value in values.items():
                            writer.writerow([f"{key}_{sub_key}", sub_value])
        elif format == 'txt':
            with open(output_file, 'w') as f:
                for key, values in self.results.items():
                    f.write(f"{key}:\n")
                    if isinstance(values, list):
                        for v in values:
                            f.write(f"  - {v}\n")
                    elif isinstance(values, dict):
                        for sub_key, sub_value in values.items():
                            f.write(f"  - {sub_key}: {sub_value}\n")
        elif format == 'markdown':
            with open(output_file, 'w') as f:
                f.write(f"# DNS Enumeration Results for {self.domain}\n\n")
                for key, values in self.results.items():
                    f.write(f"## {key.replace('_', ' ').title()}\n")
                    if isinstance(values, list) and values:
                        for v in values:
                            f.write(f"- {v}\n")
                    elif isinstance(values, dict) and values:
                        for sub_key, sub_value in values.items():
                            f.write(f"- {sub_key}: {sub_value}\n")
                    else:
                        f.write("- No records found\n")
        elif format == 'html':
            with open(output_file, 'w') as f:
                f.write(f"<html><head><title>DNS Results for {self.domain}</title></head><body>")
                f.write(f"<h1>DNS Enumeration Results for {self.domain}</h1>")
                for key, values in self.results.items():
                    f.write(f"<h2>{key.replace('_', ' ').title()}</h2><ul>")
                    if isinstance(values, list) and values:
                        for v in values:
                            f.write(f"<li>{v}</li>")
                    elif isinstance(values, dict) and values:
                        for sub_key, sub_value in values.items():
                            f.write(f"<li>{sub_key}: {sub_value}</li>")
                    else:
                        f.write("<li>No records found</li>")
                    f.write("</ul>")
                f.write("</body></html>")
        else:  # json
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=4)
        logger.info(f"Results saved to {output_file}")

    def print_results(self) -> None:
        print(f"\n=== Yesilho's DNS Enumeration Results for {self.domain} ===")
        record_types = {
            'A Records': 'a_records', 'AAAA Records': 'aaaa_records', 'MX Records': 'mx_records',
            'TXT Records': 'txt_records', 'NS Records': 'ns_records', 'CNAME Records': 'cname_records',
            'SOA Records': 'soa_records', 'SRV Records': 'srv_records', 'CAA Records': 'caa_records',
            'PTR Records': 'ptr_records'
        }
        for title, key in record_types.items():
            print(f"\n{title}:")
            if self.results[key]:
                for record in self.results[key]:
                    print(f"  - {record}")
            else:
                print("  - No records found")
        print("\nSubdomains:")
        for subdomain in self.results['subdomains']:
            print(f"  - {subdomain}") if subdomain else print("  - No subdomains found")
        if self.results['subdomain_cnames']:
            print("\nSubdomain CNAME Records:")
            for subdomain, cname in self.results['subdomain_cnames'].items():
                print(f"  - {subdomain}: {cname}")
        print("\nTLD Variations:")
        for tld_var in self.results['tld_variations']:
            print(f"  - {tld_var}") if tld_var else print("  - No TLD variations found")
        if self.results['ip_ranges']:
            print("\nReverse DNS Results:")
            for ip_range in self.results['ip_ranges']:
                print(f"  - {ip_range}")
        print("\nWHOIS Information:")
        if self.results['whois_info']:
            for key, value in self.results['whois_info'].items():
                print(f"  {key.replace('_', ' ').title()}: {value}")
        else:
            print("  - No WHOIS information available")
        if self.results['zone_transfer']:
            print("\nZone Transfer Data:")
            for data in self.results['zone_transfer']:
                print(f"  - {data}")
        if self.results['vulnerabilities']:
            print("\nVulnerabilities:")
            for vuln in self.results['vulnerabilities']:
                print(f"  - {vuln}")
        print("\n=== Summary ===")
        print(f"- A Records: {len(self.results['a_records'])}")
        print(f"- Subdomains: {len(self.results['subdomains'])}")
        print(f"- TLD Variations: {len(self.results['tld_variations'])}")
        print(f"- Vulnerabilities: {len(self.results['vulnerabilities'])}")
        if not self.results['subdomains'] and not self.results['tld_variations']:
            print("[*] Tip: Try --passive for more subdomains or -b for TLD brute-forcing.")


def print_banner():
    banner = r"""
    ██████╗   ██████╗ ███████╗███████╗
    ██╔══██╗ ██╔════╝ ██╔════╝██╔════╝
    ██║  ██║ ██║  ███╗█████╗  █████╗  
    ██║  ██║ ██║   ██║██╔══╝  ██╔══╝  
    ██████╔╝ ╚██████╔╝███████╗██║     
    ╚═════╝   ╚═════╝ ╚══════╝╚═╝     

    ╔════════════════════════════════════╗
    ║  D G E F DNS ENUMERATOR v1.0 - HAX ║
    ╚════════════════════════════════════╝
    
    >>> Deployed by Yesilho for SupNum Crew
    >>> GitHub: https://github.com/ahmedEssyad
    >>> Portfolio: https://ahmedessyad.github.io/portfolio/
    
    """
    print(banner)
def print_usage():
    usage = """
Usage: python dns_enumeration_tool2.py [options] <domain>

Options:
  -s, --subdomains FILE   Custom subdomain wordlist
  -t, --threads NUM       Number of threads (default: 20)
  -o, --output DIR        Output directory (default: dns_results)
  -r, --reverse           Enable reverse DNS lookups
  -b, --tld-brute         Enable TLD brute-forcing
  -v, --verbose           Enable verbose output
  --format FMT            Output format (json, csv, txt, markdown, html; default: json)
  --passive               Enable passive subdomain enumeration (free sources)
  --vuln-check            Check for DNS vulnerabilities
  --dns SERVER            Custom DNS server (default: 8.8.8.8)
  --debug                 Enable debug output for detailed errors
  --proxy PROXY           Proxy for HTTP requests (e.g., http://proxy:port)
  --log-level LEVEL       Logging level (INFO, WARNING, ERROR, DEBUG; default: INFO)

Example:
  python dns_enumeration_tool2.py example.com -v -s subdomains.txt -b --format markdown --dns 8.8.8.8 --passive
"""
    print(usage)

def get_subdomain_file():
    """Helper function to handle subdomain file input with error checking."""
    while True:
        filepath = input("Subdomain file? (path or Enter for default): ").strip()
        if not filepath:
            return None
        try:
            return open(filepath, 'r')
        except FileNotFoundError:
            print(f"[!] File '{filepath}' not found. Please try again or press Enter for default.")

def main():
    print_banner()
    if len(sys.argv) < 2:
        domain = input("Enter domain: ").strip()
        if not domain:
            print_usage()
            sys.exit(1)
        args = argparse.Namespace(
            domain=domain,
            verbose=input("Verbose output? (y/n): ").lower() == 'y',
            subdomains=get_subdomain_file() if input("Use custom subdomains? (y/n): ").lower() == 'y' else None,
            threads=int(input("Threads (default 20): ") or 20),
            output=input("Output directory (default dns_results): ") or "dns_results",
            reverse=input("Reverse DNS? (y/n): ").lower() == 'y',
            tld_brute=input("TLD brute-forcing? (y/n): ").lower() == 'y',
            format=input("Output format (json/csv/txt/markdown/html, default json): ") or 'json',
            passive=input("Passive recon? (y/n): ").lower() == 'y',
            vuln_check=input("Vulnerability check? (y/n): ").lower() == 'y',
            dns=input("Custom DNS server (e.g., 8.8.8.8, Enter for default): ") or None,
            debug=input("Debug mode? (y/n): ").lower() == 'y',
            proxy=input("Proxy (e.g., http://localhost:8080, Enter for none): ") or None,
            log_level=input("Log level (INFO/WARNING/ERROR/DEBUG, default INFO): ") or 'INFO'
        )
    else:
        parser = argparse.ArgumentParser(description="Yesilho's Enhanced DJEV DNS Enumeration Tool")
        parser.add_argument('domain', help="Domain to enumerate")
        parser.add_argument('-s', '--subdomains', type=argparse.FileType('r'), help="Custom subdomain wordlist file")
        parser.add_argument('-t', '--threads', type=int, default=20, help="Number of threads for enumeration")
        parser.add_argument('-o', '--output', default="dns_results", help="Output directory for results")
        parser.add_argument('-r', '--reverse', action='store_true', help="Enable reverse DNS lookups")
        parser.add_argument('-b', '--tld-brute', action='store_true', help="Enable TLD brute-forcing")
        parser.add_argument('-v', '--verbose', action='store_true', help="Enable verbose output")
        parser.add_argument('--format', choices=['json', 'csv', 'txt', 'markdown', 'html'], default='json', help="Output format")
        parser.add_argument('--passive', action='store_true', help="Enable passive subdomain enumeration (free sources)")
        parser.add_argument('--vuln-check', action='store_true', help="Check for DNS vulnerabilities")
        parser.add_argument('--dns', default="8.8.8.8", help="Custom DNS server (default: 8.8.8.8)")
        parser.add_argument('--debug', action='store_true', help="Enable debug output for detailed errors")
        parser.add_argument('--proxy', help="Proxy for HTTP requests (e.g., http://proxy:port)")
        parser.add_argument('--log-level', choices=['INFO', 'WARNING', 'ERROR', 'DEBUG'], default='INFO', help="Logging level")
        args = parser.parse_args()

    dns_enum = DNSEnumerationTool(args.domain, args.output, args.dns, args.debug, args.proxy, args.log_level)
    if args.subdomains:
        custom_subdomains = [line.strip() for line in args.subdomains if line.strip()]
        dns_enum.enumerate_subdomains(custom_subdomains, args.threads)
    dns_enum.run_full_enumeration(threads=args.threads, reverse=args.reverse, tld_brute=args.tld_brute,
                                  passive=args.passive, vuln_check=args.vuln_check)
    if args.verbose:
        dns_enum.print_results()
    dns_enum.save_results(args.format)

if __name__ == "__main__":
    main()

# Required Dependencies:
# pip install dnspython python-whois requests tqdm
