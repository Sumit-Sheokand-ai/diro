# DIRO - Multi-Task Ethical Hacking Tool

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)

A comprehensive, menu-driven ethical hacking tool designed for penetration testers and security researchers. DIRO provides multiple reconnaissance and analysis modules in a single, easy-to-use interface.

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is provided for educational and authorized security testing purposes only. Unauthorized access to computer systems, networks, or data is illegal and may result in criminal prosecution. By using this tool, you agree to:

- Only test systems you own or have explicit written permission to test
- Comply with all applicable laws and regulations
- Accept full responsibility for any consequences of your actions

The authors are not responsible for any misuse or damage caused by this tool.

## ✨ Features

### 🔍 Network Reconnaissance
- **Network Scanner**: Host discovery and IP resolution
- **Port Scanner**: Multi-threaded port scanning with service detection
- **Subdomain Enumeration**: Discover subdomains for a target domain
- **DNS Lookup**: Forward and reverse DNS queries
- **Ping Sweep**: Discover active hosts on a network

### 🌐 Web Analysis
- **HTTP Header Analysis**: Examine server headers and security configurations
- **Security Header Detection**: Check for HSTS, CSP, and other security headers
- **SSL Certificate Information**: Analyze SSL/TLS configurations

### 🔐 Cryptography
- **Hash Analyzer**: Identify hash types (MD5, SHA1, SHA256, etc.)
- **Hash Generator**: Create hashes with multiple algorithms

### 🔧 Additional Tools
- **WHOIS Lookup**: Domain registration information
- **Reverse IP Lookup**: Find hostnames associated with IP addresses

## 📋 Requirements

- Python 3.6 or higher
- Linux-based OS (tested on Kali Linux)
- Root/sudo privileges for some features

## 🚀 Installation

### Quick Install (Kali Linux)

```bash
# Clone the repository
git clone https://github.com/yourusername/diro.git
cd diro

# Make the installation script executable
chmod +x install.sh

# Run the installer (requires sudo)
sudo ./install.sh
```

### Manual Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/diro.git
cd diro

# Install Python dependencies
pip3 install -r requirements.txt

# Make the script executable
chmod +x diro.py

# (Optional) Create a symbolic link for system-wide access
sudo ln -s $(pwd)/diro.py /usr/local/bin/diro
```

## 📖 Usage

### Basic Usage

```bash
# Run from the installation directory
python3 diro.py

# Or if installed system-wide
diro
```

### Example Workflows

#### Port Scanning
1. Select option `[2] Port Scanner`
2. Enter target IP address
3. Choose port range or select "common" for common ports
4. View results

#### Subdomain Enumeration
1. Select option `[3] Subdomain Enumeration`
2. Enter domain (e.g., example.com)
3. Wait for results

#### Web Header Analysis
1. Select option `[5] Web Header Analysis`
2. Enter URL
3. Review HTTP headers and security configuration

## 🛠️ Module Details

### Network Scanner
- Resolves hostnames to IP addresses
- Performs reverse DNS lookups
- Identifies target information

### Port Scanner
- Multi-threaded for fast scanning
- Identifies common services (SSH, HTTP, MySQL, etc.)
- Customizable port ranges
- Quick scan with predefined common ports

### Subdomain Enumeration
- Tests common subdomain names
- Resolves to IP addresses
- Identifies active subdomains

### Hash Analyzer
- **Identify**: Detects hash type by length
- **Generate**: Creates hashes using MD5, SHA1, SHA256, SHA512

### Web Analyzer
- Fetches and displays HTTP headers
- Checks for security headers:
  - Strict-Transport-Security (HSTS)
  - X-Content-Type-Options
  - X-Frame-Options
  - Content-Security-Policy
  - X-XSS-Protection

### Ping Sweep
- Scans entire subnet (254 hosts)
- Platform-independent (Windows/Linux)
- Identifies live hosts

## 🎯 Use Cases

- **Penetration Testing**: Initial reconnaissance phase
- **Security Audits**: Check for exposed services
- **Network Inventory**: Discover active hosts
- **Web Security**: Analyze HTTP security headers
- **CTF Competitions**: Quick enumeration tool
- **Education**: Learn about network security

## 🔧 Advanced Configuration

### Custom Subdomain Wordlist
Edit the `subdomains` list in `SubdomainEnum.enumerate()` to add custom subdomain names.

### Adjusting Thread Count
Modify the `threads` parameter in `PortScanner.scan_ports()` for faster or slower scanning.

### Timeout Configuration
Change the `timeout` value in `PortScanner.scan_port()` for slower networks.

## 📝 Examples

### Scan Common Ports
```
Select option: 2
Enter target IP: 192.168.1.1
Enter port range: common
```

### Generate SHA256 Hash
```
Select option: 4
Select: 2
Enter text to hash: mypassword
Algorithm: sha256
```

### Check Website Security Headers
```
Select option: 5
Enter URL: https://example.com
```

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚡ Roadmap

- [ ] Add vulnerability scanning modules
- [ ] Implement SQL injection testing
- [ ] Add XSS detection
- [ ] Create export functionality (JSON/CSV/HTML reports)
- [ ] Add more hash algorithms
- [ ] Implement custom wordlist support
- [ ] Add API integrations (Shodan, VirusTotal)
- [ ] Create GUI version

## 🐛 Known Issues

- Ping sweep may be slow on large networks
- Some features require root privileges
- Color output may not work on all terminals

## 📞 Support

For questions, issues, or feature requests:
- Open an issue on GitHub
- Contact: [your-email@example.com]

## 🙏 Acknowledgments

- Thanks to the security research community
- Inspired by tools like Nmap, Metasploit, and Recon-ng
- Built for educational purposes

## 📚 Resources

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)
- [Kali Linux Documentation](https://www.kali.org/docs/)

---

**Remember**: Always get proper authorization before testing any systems!

Made with ❤️ for the security community
