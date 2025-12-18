# DIRO Quick Start Guide

Get up and running with DIRO in minutes!

## Installation (One-Liner)

```bash
git clone https://github.com/yourusername/diro.git && cd diro && sudo ./install.sh
```

## First Run

```bash
diro
```

Or:

```bash
python3 diro.py
```

## Quick Examples

### 1. Scan a Host
```
Select option: 1
Enter target hostname/IP: google.com
```
**Output**: IP address and hostname information

### 2. Quick Port Scan
```
Select option: 2
Enter target IP: 192.168.1.1
Enter port range: common
```
**Output**: List of open ports with service names

### 3. Find Subdomains
```
Select option: 3
Enter domain: example.com
```
**Output**: Active subdomains with IPs

### 4. Check Website Security
```
Select option: 5
Enter URL: https://example.com
```
**Output**: HTTP headers and security configuration

### 5. Identify Hash
```
Select option: 4
Select: 1
Enter hash: 5f4dcc3b5aa765d61d8327deb882cf99
```
**Output**: MD5 (identified by length)

### 6. Network Discovery
```
Select option: 10
Enter network: 192.168.1.0
```
**Output**: All active hosts on the network

## Common Workflows

### Web Application Assessment
1. DNS Lookup (option 6) → Find IP
2. Subdomain Enum (option 3) → Discover subdomains
3. Port Scan (option 2) → Find services
4. Header Analysis (option 5) → Check security

### Network Audit
1. Ping Sweep (option 10) → Find hosts
2. Port Scan (option 2) → Check each host
3. Reverse Lookup (option 7) → Identify machines

### Hash Analysis
1. Hash Analyzer (option 4)
2. Choose: Identify (1) or Generate (2)
3. Enter hash or text

## Tips

### Speed Up Port Scans
- Use "common" instead of large ranges
- Scan specific ports: `80-443`
- Run during off-peak hours

### Better Results
- Use domain names instead of IPs when possible
- Try both www and non-www versions
- Check multiple subdomains manually if needed

### Troubleshooting

**Colors not showing?**
- Check terminal supports ANSI colors
- Try a different terminal emulator

**Permission denied?**
- Some features need sudo/root
- Run: `sudo python3 diro.py`

**Slow scans?**
- Reduce port range
- Check network speed
- Scan fewer hosts at once

**Module not found?**
- Install dependencies: `pip3 install -r requirements.txt`
- Check Python version: `python3 --version`

## Keyboard Shortcuts

- **Ctrl+C**: Exit current operation
- **Enter**: Continue after results
- **0**: Exit program

## Pro Tips

1. **Save Results**: Redirect output
   ```bash
   python3 diro.py > results.txt
   ```

2. **Background Execution**:
   ```bash
   nohup python3 diro.py &
   ```

3. **Combine with Other Tools**:
   ```bash
   # Use DIRO output with other tools
   diro | grep "OPEN"
   ```

4. **Automate Tests**:
   Create a script to feed inputs automatically

## Common Port Numbers

| Port  | Service       |
|-------|---------------|
| 21    | FTP           |
| 22    | SSH           |
| 23    | Telnet        |
| 25    | SMTP          |
| 80    | HTTP          |
| 443   | HTTPS         |
| 3306  | MySQL         |
| 3389  | RDP           |
| 5432  | PostgreSQL    |
| 8080  | HTTP Proxy    |

## Legal Reminders

✅ **Do**:
- Test your own systems
- Get written permission
- Follow responsible disclosure
- Document your findings

❌ **Don't**:
- Scan without permission
- Ignore warnings
- Test production systems without approval
- Share unauthorized findings

## Next Steps

1. Read the full [README.md](README.md)
2. Review [CONTRIBUTING.md](CONTRIBUTING.md) to add features
3. Check [CHANGELOG.md](CHANGELOG.md) for updates
4. Report issues on GitHub

## Getting Help

**Question**: How do I scan multiple hosts?
**Answer**: Run ping sweep first, then scan each host individually

**Question**: Can I export results?
**Answer**: Use output redirection: `python3 diro.py > output.txt`

**Question**: How to scan faster?
**Answer**: Reduce port range or use "common" preset

**Question**: Tool not working?
**Answer**: 
1. Check Python version (3.6+)
2. Install dependencies
3. Check network connection
4. Try with sudo

## Resources

- [Nmap Documentation](https://nmap.org/docs.html)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Kali Linux Tools](https://www.kali.org/tools/)

---

Ready to start? Run `diro` and select option 1!

**Remember**: Always hack ethically and legally! 🛡️
