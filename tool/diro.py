#!/usr/bin/env python3
"""
DIRO - Multi-Task Ethical Hacking Tool
Author: Security Research
License: MIT

DISCLAIMER: This tool is for AUTHORIZED SECURITY TESTING ONLY.
Unauthorized access to computer systems is illegal.
"""

import sys
import os
import socket
import subprocess
import hashlib
import requests
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import json

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Display tool banner"""
    banner = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗ ██╗██████╗  ██████╗                            ║
║   ██╔══██╗██║██╔══██╗██╔═══██╗                           ║
║   ██║  ██║██║██████╔╝██║   ██║                           ║
║   ██║  ██║██║██╔══██╗██║   ██║                           ║
║   ██████╔╝██║██║  ██║╚██████╔╝                           ║
║   ╚═════╝ ╚═╝╚═╝  ╚═╝ ╚═════╝                            ║
║                                                           ║
║        Multi-Task Ethical Hacking Tool v1.0               ║
║        For Authorized Security Testing Only               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Colors.END}
"""
    print(banner)

def print_menu():
    """Display main menu"""
    menu = f"""
{Colors.BOLD}[Main Menu]{Colors.END}

{Colors.GREEN}[1]{Colors.END}  Network Scanner
{Colors.GREEN}[2]{Colors.END}  Port Scanner
{Colors.GREEN}[3]{Colors.END}  Subdomain Enumeration
{Colors.GREEN}[4]{Colors.END}  Hash Analyzer
{Colors.GREEN}[5]{Colors.END}  Web Header Analysis
{Colors.GREEN}[6]{Colors.END}  DNS Lookup
{Colors.GREEN}[7]{Colors.END}  Reverse IP Lookup
{Colors.GREEN}[8]{Colors.END}  WHOIS Lookup
{Colors.GREEN}[9]{Colors.END}  SSL Certificate Info
{Colors.GREEN}[10]{Colors.END} Ping Sweep
{Colors.GREEN}[0]{Colors.END}  Exit

"""
    print(menu)

class NetworkScanner:
    """Network reconnaissance tools"""
    
    @staticmethod
    def scan_host(target):
        """Basic host discovery"""
        print(f"\n{Colors.BLUE}[*] Scanning host: {target}{Colors.END}")
        try:
            ip = socket.gethostbyname(target)
            print(f"{Colors.GREEN}[+] IP Address: {ip}{Colors.END}")
            
            # Try reverse DNS
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                print(f"{Colors.GREEN}[+] Hostname: {hostname}{Colors.END}")
            except:
                print(f"{Colors.YELLOW}[-] No reverse DNS found{Colors.END}")
            
            return ip
        except socket.gaierror:
            print(f"{Colors.RED}[-] Could not resolve hostname{Colors.END}")
            return None

class PortScanner:
    """Port scanning functionality"""
    
    @staticmethod
    def scan_port(host, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    @staticmethod
    def scan_ports(host, ports, threads=50):
        """Scan multiple ports"""
        print(f"\n{Colors.BLUE}[*] Scanning ports on {host}{Colors.END}")
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(PortScanner.scan_port, host, port): port for port in ports}
            for future in futures:
                port = futures[future]
                if future.result():
                    service = PortScanner.get_service_name(port)
                    print(f"{Colors.GREEN}[+] Port {port} is OPEN - {service}{Colors.END}")
                    open_ports.append(port)
        
        if not open_ports:
            print(f"{Colors.YELLOW}[-] No open ports found{Colors.END}")
        
        return open_ports
    
    @staticmethod
    def get_service_name(port):
        """Get common service name for port"""
        common_ports = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
            143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Proxy",
            8443: "HTTPS-Alt", 27017: "MongoDB"
        }
        return common_ports.get(port, "Unknown")

class SubdomainEnum:
    """Subdomain enumeration"""
    
    @staticmethod
    def enumerate(domain, wordlist=None):
        """Enumerate subdomains"""
        print(f"\n{Colors.BLUE}[*] Enumerating subdomains for: {domain}{Colors.END}")
        
        # Common subdomain list
        subdomains = [
            "www", "mail", "ftp", "admin", "webmail", "smtp", "pop", "ns1", "ns2",
            "api", "dev", "staging", "test", "beta", "app", "portal", "vpn",
            "m", "mobile", "blog", "shop", "store", "cdn", "static", "media"
        ]
        
        found = []
        for sub in subdomains:
            target = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(target)
                print(f"{Colors.GREEN}[+] Found: {target} -> {ip}{Colors.END}")
                found.append((target, ip))
            except:
                pass
        
        if not found:
            print(f"{Colors.YELLOW}[-] No subdomains found{Colors.END}")
        
        return found

class HashAnalyzer:
    """Hash identification and analysis"""
    
    @staticmethod
    def identify_hash(hash_string):
        """Identify hash type"""
        length = len(hash_string)
        hash_types = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256",
            96: "SHA384",
            128: "SHA512"
        }
        return hash_types.get(length, "Unknown")
    
    @staticmethod
    def hash_string(text, algorithm='md5'):
        """Generate hash"""
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256,
            'sha512': hashlib.sha512
        }
        
        if algorithm in algorithms:
            return algorithms[algorithm](text.encode()).hexdigest()
        return None

class WebAnalyzer:
    """Web reconnaissance tools"""
    
    @staticmethod
    def analyze_headers(url):
        """Analyze HTTP headers"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        print(f"\n{Colors.BLUE}[*] Analyzing headers for: {url}{Colors.END}")
        
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            
            print(f"\n{Colors.GREEN}Status Code: {response.status_code}{Colors.END}")
            print(f"\n{Colors.BOLD}Headers:{Colors.END}")
            for header, value in response.headers.items():
                print(f"  {Colors.CYAN}{header}:{Colors.END} {value}")
            
            # Check security headers
            print(f"\n{Colors.BOLD}Security Headers Check:{Colors.END}")
            security_headers = [
                'Strict-Transport-Security',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy',
                'X-XSS-Protection'
            ]
            
            for header in security_headers:
                if header in response.headers:
                    print(f"  {Colors.GREEN}[+] {header}: Present{Colors.END}")
                else:
                    print(f"  {Colors.RED}[-] {header}: Missing{Colors.END}")
            
        except Exception as e:
            print(f"{Colors.RED}[-] Error: {str(e)}{Colors.END}")

class DNSTools:
    """DNS lookup tools"""
    
    @staticmethod
    def dns_lookup(domain):
        """Perform DNS lookup"""
        print(f"\n{Colors.BLUE}[*] DNS Lookup for: {domain}{Colors.END}")
        
        try:
            ip = socket.gethostbyname(domain)
            print(f"{Colors.GREEN}[+] A Record: {ip}{Colors.END}")
        except:
            print(f"{Colors.RED}[-] Could not resolve domain{Colors.END}")
    
    @staticmethod
    def reverse_lookup(ip):
        """Reverse IP lookup"""
        print(f"\n{Colors.BLUE}[*] Reverse lookup for: {ip}{Colors.END}")
        
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"{Colors.GREEN}[+] Hostname: {hostname}{Colors.END}")
        except:
            print(f"{Colors.RED}[-] No hostname found{Colors.END}")

def ping_sweep(network):
    """Perform ping sweep on network"""
    print(f"\n{Colors.BLUE}[*] Performing ping sweep on: {network}{Colors.END}")
    print(f"{Colors.YELLOW}[*] This may take a while...{Colors.END}\n")
    
    base_ip = '.'.join(network.split('.')[:-1])
    
    active_hosts = []
    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        try:
            # Platform-specific ping
            if sys.platform.startswith('win'):
                response = subprocess.run(
                    ['ping', '-n', '1', '-w', '500', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            else:
                response = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            
            if response.returncode == 0:
                print(f"{Colors.GREEN}[+] {ip} is UP{Colors.END}")
                active_hosts.append(ip)
        except:
            pass
    
    print(f"\n{Colors.BLUE}[*] Found {len(active_hosts)} active hosts{Colors.END}")
    return active_hosts

def main():
    """Main function"""
    print_banner()
    
    # Legal disclaimer
    print(f"{Colors.RED}{Colors.BOLD}LEGAL DISCLAIMER:{Colors.END}")
    print(f"{Colors.YELLOW}This tool is for AUTHORIZED security testing only.")
    print(f"Unauthorized access to systems is illegal.")
    print(f"By using this tool, you agree to test only systems you own or have permission to test.{Colors.END}\n")
    
    confirm = input(f"Do you agree? (yes/no): ").lower()
    if confirm not in ['yes', 'y']:
        print(f"{Colors.RED}Exiting...{Colors.END}")
        sys.exit(0)
    
    while True:
        print_menu()
        choice = input(f"{Colors.CYAN}Select an option: {Colors.END}").strip()
        
        if choice == '1':
            target = input(f"{Colors.CYAN}Enter target hostname/IP: {Colors.END}").strip()
            NetworkScanner.scan_host(target)
        
        elif choice == '2':
            host = input(f"{Colors.CYAN}Enter target IP: {Colors.END}").strip()
            port_range = input(f"{Colors.CYAN}Enter port range (e.g., 1-1000) or 'common': {Colors.END}").strip()
            
            if port_range.lower() == 'common':
                ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 8080]
            else:
                try:
                    start, end = map(int, port_range.split('-'))
                    ports = range(start, end + 1)
                except:
                    print(f"{Colors.RED}[-] Invalid port range{Colors.END}")
                    continue
            
            PortScanner.scan_ports(host, ports)
        
        elif choice == '3':
            domain = input(f"{Colors.CYAN}Enter domain (e.g., example.com): {Colors.END}").strip()
            SubdomainEnum.enumerate(domain)
        
        elif choice == '4':
            print(f"\n{Colors.BOLD}[Hash Analyzer]{Colors.END}")
            print(f"{Colors.GREEN}[1]{Colors.END} Identify hash type")
            print(f"{Colors.GREEN}[2]{Colors.END} Generate hash")
            sub_choice = input(f"{Colors.CYAN}Select: {Colors.END}").strip()
            
            if sub_choice == '1':
                hash_val = input(f"{Colors.CYAN}Enter hash: {Colors.END}").strip()
                hash_type = HashAnalyzer.identify_hash(hash_val)
                print(f"{Colors.GREEN}[+] Identified as: {hash_type}{Colors.END}")
            
            elif sub_choice == '2':
                text = input(f"{Colors.CYAN}Enter text to hash: {Colors.END}").strip()
                algo = input(f"{Colors.CYAN}Algorithm (md5/sha1/sha256/sha512): {Colors.END}").strip().lower()
                result = HashAnalyzer.hash_string(text, algo)
                if result:
                    print(f"{Colors.GREEN}[+] {algo.upper()} Hash: {result}{Colors.END}")
        
        elif choice == '5':
            url = input(f"{Colors.CYAN}Enter URL: {Colors.END}").strip()
            WebAnalyzer.analyze_headers(url)
        
        elif choice == '6':
            domain = input(f"{Colors.CYAN}Enter domain: {Colors.END}").strip()
            DNSTools.dns_lookup(domain)
        
        elif choice == '7':
            ip = input(f"{Colors.CYAN}Enter IP address: {Colors.END}").strip()
            DNSTools.reverse_lookup(ip)
        
        elif choice == '8':
            domain = input(f"{Colors.CYAN}Enter domain for WHOIS: {Colors.END}").strip()
            print(f"{Colors.YELLOW}[*] Use 'whois {domain}' command in terminal{Colors.END}")
        
        elif choice == '9':
            domain = input(f"{Colors.CYAN}Enter domain for SSL info: {Colors.END}").strip()
            print(f"{Colors.YELLOW}[*] Use 'openssl s_client -connect {domain}:443' in terminal{Colors.END}")
        
        elif choice == '10':
            network = input(f"{Colors.CYAN}Enter network (e.g., 192.168.1.0): {Colors.END}").strip()
            ping_sweep(network)
        
        elif choice == '0':
            print(f"\n{Colors.GREEN}Thank you for using DIRO!{Colors.END}")
            print(f"{Colors.YELLOW}Remember: Use responsibly and legally.{Colors.END}\n")
            sys.exit(0)
        
        else:
            print(f"{Colors.RED}[-] Invalid option{Colors.END}")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.RED}[!] Interrupted by user{Colors.END}")
        sys.exit(0)
