# DNS Enumeration Tool 🌐🔍

![DNS Enumeration Banner](https://via.placeholder.com/800x200.png?text=DNS+Enumeration+Tool)

*Fast, lightweight DNS enumeration for security researchers and network professionals.*

## 📝 Overview

The DNS Enumeration Tool is a powerful Python-based utility designed to help security researchers, network administrators, and cybersecurity professionals discover comprehensive DNS information for a given domain.

## 🚀 Features

- **Subdomain Discovery**: Advanced subdomain enumeration using custom wordlists
- **TLD Variations**: Identify potential domain variations
- **Comprehensive Record Lookup**:
  - A Records
  - MX Records
  - TXT Records
  - NS Records
- **WHOIS Insights**: Optional detailed domain registration information
- **Performance Optimized**: 
  - Multi-threaded architecture
  - Asynchronous processing
- **Flexible Output**: 
  - Detailed JSON reports
  - Verbose console logging

## 🛠 Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup Steps

1. Clone the Repository
```bash
git clone https://github.com/ahmedEssyad/dns-enumeration-tool.git
cd dns-enumeration-tool
```

2. Install Dependencies
```bash
pip install -r requirements.txt
```

## 💻 Usage

### Basic Command
```bash
python dns_enumeration_tool.py example.com -v
```

### Advanced Options
```bash
python dns_enumeration_tool.py tesla.com -v -s subdomains.txt -b -t 50
```

### Command Line Options
| Flag | Description | Default |
|------|-------------|---------|
| `-s <file>` | Custom subdomain wordlist | Built-in list |
| `-t <int>` | Max concurrent tasks | 20 |
| `-b` | Enable TLD brute-forcing | Disabled |
| `-r` | Fetch WHOIS info | Disabled |
| `-v` | Verbose output | Disabled |

## 📄 Output Format
Results are saved as JSON in `dns_results/[domain]_[timestamp].json`

Example Output:
```json
{
  "domain": "tesla.com",
  "a_records": [
    "2.18.55.207", 
    "23.40.100.207"
  ],
  "subdomains": [
    "www.tesla.com", 
    "shop.tesla.com"
  ],
  "tld_variations": [
    "tesla.com", 
    "tesla.org"
  ]
}
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 🛡 Ethical Usage

**Important**: This tool is intended for authorized security research and network administration. Always obtain proper permissions before scanning domains you do not own.

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## 🙏 Acknowledgments

- Created by A. Essyad for SupNum Crew
- Inspired by open-source tools like dnsdumpster and subfinder

---

**Disclaimer**: Use responsibly and ethically. Unauthorized scanning may be illegal.
