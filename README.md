# DNS Enumeration Tool

![Banner](https://via.placeholder.com/800x200.png?text=DNS+Enumeration+Tool)  
*Fast, lightweight DNS enumeration for security researchers and enthusiasts.*

---

## What It Does
This tool performs DNS enumeration to discover subdomains, TLD variations, and DNS records (A, MX, TXT, NS, etc.) for a given domain. Built with Python, it’s designed to be efficient and easy to extend.

### Features
- Subdomain enumeration with custom wordlists
- TLD brute-forcing
- Standard DNS record lookups
- Optional WHOIS data retrieval
- Multi-threaded/async for speed
- JSON output for easy parsing

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/[your-username]/dns-enumeration-tool.git
   cd dns-enumeration-tool
2 Install dependencies:
   pip install -r requirements.txt
3 Usage
   Basic command:
   python dns_enumeration_tool.py example.com -v
    Options
    -s <file>: Custom subdomain wordlist
    -t <int>: Max concurrent tasks (default: 20)
    -b: Enable TLD brute-forcing
    -r: Fetch WHOIS info
    -v: Verbose output

Example with wordlist and TLD brute-forcing:

python dns_enumeration_tool.py tesla.com -v -s subdomains.txt -b -t 50


   Output is saved to dns_results/[domain]_[timestamp].json.
   
Exemple of the  OutPut
{
  "a_records": ["2.18.55.207", "23.40.100.207"],
  "subdomains": ["www.tesla.com", "shop.tesla.com"],
  "tld_variations": ["tesla.com", "tesla.org"]
}
4 Contributing
We’d love your help! Check out  for guidelines on how to get involved.

5 License
This project is licensed under the MIT License - see  for details.

6 Acknowledgments
Built by A essyad for the SupNum Crew
Inspired by open-source tools like dnsdumpster and subfinder
