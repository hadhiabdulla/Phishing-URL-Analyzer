#!/usr/bin/env python3
"""
Phishing URL Analyzer
A comprehensive tool to analyze URLs and detect phishing attempts
using multiple detection techniques.

Author: Cybersecurity Analysis Tool
License: MIT
"""

import re
import ssl
import socket
import requests
from urllib.parse import urlparse
import whois
from datetime import datetime
import argparse
import json
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

class PhishingAnalyzer:
    """Main class for analyzing URLs and detecting phishing indicators"""
    
    def __init__(self, url):
        self.url = url
        self.parsed_url = urlparse(url)
        self.domain = self.parsed_url.netloc
        self.results = {
            'url': url,
            'risk_score': 0,
            'checks': {},
            'verdict': ''
        }
    
    def analyze(self):
        """Run all phishing detection checks"""
        print(f"{Fore.CYAN}[*] Analyzing URL: {self.url}{Style.RESET_ALL}")
        print("="*60)
        
        # Run individual checks
        self.check_url_length()
        self.check_suspicious_keywords()
        self.check_ip_address()
        self.check_https_ssl()
        self.check_url_shortener()
        self.check_subdomain_count()
        self.check_special_characters()
        self.check_domain_age()
        
        # Calculate final verdict
        self.calculate_verdict()
        
        return self.results
    
    def check_url_length(self):
        """Check if URL length is suspiciously long"""
        length = len(self.url)
        suspicious = length > 75
        
        self.results['checks']['url_length'] = {
            'value': length,
            'suspicious': suspicious,
            'weight': 5 if suspicious else 0
        }
        
        if suspicious:
            self.results['risk_score'] += 5
            print(f"{Fore.YELLOW}[!] URL length ({length}) is suspiciously long{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] URL length ({length}) appears normal{Style.RESET_ALL}")
    
    def check_suspicious_keywords(self):
        """Check for common phishing keywords in URL"""
        phishing_keywords = [
            'login', 'signin', 'account', 'update', 'verify', 'secure',
            'banking', 'paypal', 'amazon', 'confirm', 'suspend', 'verify'
        ]
        
        found_keywords = [kw for kw in phishing_keywords if kw in self.url.lower()]
        suspicious = len(found_keywords) >= 2
        
        self.results['checks']['suspicious_keywords'] = {
            'found': found_keywords,
            'suspicious': suspicious,
            'weight': 15 if suspicious else 5 if found_keywords else 0
        }
        
        if suspicious:
            self.results['risk_score'] += 15
            print(f"{Fore.YELLOW}[!] Multiple suspicious keywords found: {', '.join(found_keywords)}{Style.RESET_ALL}")
        elif found_keywords:
            self.results['risk_score'] += 5
            print(f"{Fore.CYAN}[*] Found keywords: {', '.join(found_keywords)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] No suspicious keywords detected{Style.RESET_ALL}")
    
    def check_ip_address(self):
        """Check if domain is an IP address instead of domain name"""
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        is_ip = bool(ip_pattern.match(self.domain))
        
        self.results['checks']['ip_address'] = {
            'is_ip': is_ip,
            'suspicious': is_ip,
            'weight': 20 if is_ip else 0
        }
        
        if is_ip:
            self.results['risk_score'] += 20
            print(f"{Fore.RED}[!] Domain is an IP address - highly suspicious{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] Domain is not an IP address{Style.RESET_ALL}")
    
    def check_https_ssl(self):
        """Check if URL uses HTTPS and validate SSL certificate"""
        uses_https = self.parsed_url.scheme == 'https'
        ssl_valid = False
        
        if uses_https:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        ssl_valid = True
            except:
                ssl_valid = False
        
        suspicious = not uses_https or not ssl_valid
        
        self.results['checks']['https_ssl'] = {
            'uses_https': uses_https,
            'ssl_valid': ssl_valid,
            'suspicious': suspicious,
            'weight': 10 if not uses_https else 5 if not ssl_valid else 0
        }
        
        if not uses_https:
            self.results['risk_score'] += 10
            print(f"{Fore.YELLOW}[!] URL does not use HTTPS{Style.RESET_ALL}")
        elif not ssl_valid:
            self.results['risk_score'] += 5
            print(f"{Fore.YELLOW}[!] SSL certificate validation failed{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] HTTPS enabled with valid SSL certificate{Style.RESET_ALL}")
    
    def check_url_shortener(self):
        """Check if URL uses a URL shortening service"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        is_shortened = any(shortener in self.domain for shortener in shorteners)
        
        self.results['checks']['url_shortener'] = {
            'is_shortened': is_shortened,
            'suspicious': is_shortened,
            'weight': 10 if is_shortened else 0
        }
        
        if is_shortened:
            self.results['risk_score'] += 10
            print(f"{Fore.YELLOW}[!] URL uses a shortening service - potential masking{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] No URL shortener detected{Style.RESET_ALL}")
    
    def check_subdomain_count(self):
        """Check number of subdomains (excessive subdomains are suspicious)"""
        subdomain_count = self.domain.count('.')
        suspicious = subdomain_count >= 3
        
        self.results['checks']['subdomain_count'] = {
            'count': subdomain_count,
            'suspicious': suspicious,
            'weight': 10 if suspicious else 0
        }
        
        if suspicious:
            self.results['risk_score'] += 10
            print(f"{Fore.YELLOW}[!] Multiple subdomains detected ({subdomain_count}) - suspicious{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] Subdomain count ({subdomain_count}) appears normal{Style.RESET_ALL}")
    
    def check_special_characters(self):
        """Check for excessive special characters and homograph attacks"""
        special_char_pattern = re.compile(r'[@_\-]')
        special_count = len(special_char_pattern.findall(self.url))
        suspicious = special_count >= 4
        
        self.results['checks']['special_characters'] = {
            'count': special_count,
            'suspicious': suspicious,
            'weight': 10 if suspicious else 0
        }
        
        if suspicious:
            self.results['risk_score'] += 10
            print(f"{Fore.YELLOW}[!] Excessive special characters ({special_count}) detected{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] Special character count appears normal{Style.RESET_ALL}")
    
    def check_domain_age(self):
        """Check domain registration age (newer domains are more suspicious)"""
        try:
            domain_info = whois.whois(self.domain)
            creation_date = domain_info.creation_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                suspicious = age_days < 180  # Less than 6 months
                
                self.results['checks']['domain_age'] = {
                    'age_days': age_days,
                    'creation_date': str(creation_date),
                    'suspicious': suspicious,
                    'weight': 15 if suspicious else 0
                }
                
                if suspicious:
                    self.results['risk_score'] += 15
                    print(f"{Fore.YELLOW}[!] Domain is very new ({age_days} days old){Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[✓] Domain age ({age_days} days) appears legitimate{Style.RESET_ALL}")
            else:
                self.results['checks']['domain_age'] = {'error': 'Could not determine age'}
                print(f"{Fore.CYAN}[*] Could not determine domain age{Style.RESET_ALL}")
        except Exception as e:
            self.results['checks']['domain_age'] = {'error': str(e)}
            print(f"{Fore.CYAN}[*] Could not check domain age: {str(e)[:50]}{Style.RESET_ALL}")
    
    def calculate_verdict(self):
        """Calculate final verdict based on risk score"""
        score = self.results['risk_score']
        
        print("\n" + "="*60)
        print(f"{Fore.CYAN}Risk Score: {score}/100{Style.RESET_ALL}")
        
        if score >= 50:
            verdict = "HIGH RISK - Likely Phishing"
            color = Fore.RED
        elif score >= 30:
            verdict = "MEDIUM RISK - Suspicious"
            color = Fore.YELLOW
        elif score >= 15:
            verdict = "LOW RISK - Some concerns"
            color = Fore.CYAN
        else:
            verdict = "SAFE - Appears legitimate"
            color = Fore.GREEN
        
        self.results['verdict'] = verdict
        print(f"{color}Verdict: {verdict}{Style.RESET_ALL}")
        print("="*60)

def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(
        description='Analyze URLs for phishing indicators',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phishing_analyzer.py -u https://example.com
  python phishing_analyzer.py -u https://suspicious-site.com -o results.json
        """
    )
    
    parser.add_argument('-u', '--url', required=True, help='URL to analyze')
    parser.add_argument('-o', '--output', help='Output results to JSON file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    # Print banner
    print(f"{Fore.CYAN}")
    print("="*60)
    print("  PHISHING URL ANALYZER  ".center(60))
    print("  Advanced Threat Detection Tool  ".center(60))
    print("="*60)
    print(f"{Style.RESET_ALL}")
    
    # Analyze URL
    analyzer = PhishingAnalyzer(args.url)
    results = analyzer.analyze()
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"\n{Fore.GREEN}[✓] Results saved to {args.output}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
