#!/usr/bin/env python3
"""
Security Checker Module
"""
import re

class SecurityChecker:
    def __init__(self):
        self.vulnerable_networks = []
        
    def analyze_networks(self, networks):
        """Analyze networks for security vulnerabilities"""
        print("\n\033[96m" + "="*80 + "\033[0m")
        print("\033[96mSecurity Analysis Report\033[0m".center(80))
        print("\033[96m" + "="*80 + "\033[0m")
        
        vulnerable = []
        secure = []
        unknown = []
        
        for net in networks:
            vulnerabilities = self.check_vulnerabilities(net)
            
            if vulnerabilities:
                net['vulnerabilities'] = vulnerabilities
                vulnerable.append(net)
            elif net.get('wpa') and not net.get('wep'):
                secure.append(net)
            else:
                unknown.append(net)
                
        # Display results
        self.display_vulnerabilities(vulnerable)
        self.display_secure(secure)
        self.display_unknown(unknown)
        
        # Summary
        print("\n\033[96m" + "="*80 + "\033[0m")
        print("\033[96mSummary:\033[0m")
        print(f"  Vulnerable: {len(vulnerable)}")
        print(f"  Secure: {len(secure)}")
        print(f"  Unknown: {len(unknown)}")
        print("\033[96m" + "="*80 + "\033[0m")
        
        self.vulnerable_networks = vulnerable
        
        return vulnerable
        
    def check_vulnerabilities(self, network):
        """Check for specific vulnerabilities in a network"""
        vulnerabilities = []
        
        # Check for WEP
        if network.get('wep'):
            vulnerabilities.append("WEP encryption (crackable in minutes)")
            
        # Check for open networks
        if network.get('open'):
            vulnerabilities.append("No encryption (open network)")
            
        # Check for WPA with weak cipher
        if network.get('wpa'):
            if 'TKIP' in network.get('encryption', ''):
                vulnerabilities.append("WPA with TKIP (vulnerable to KRACK)")
                
            # Check for WPA2 with weak settings
            if 'WPA2' in network.get('encryption', ''):
                vulnerabilities.append("WPA2 (vulnerable to KRACK unless patched)")
                
        # Check for WPS (we can check from encryption field)
        if 'WPS' in network.get('encryption', ''):
            vulnerabilities.append("WPS enabled (vulnerable to brute force)")
            
        return vulnerabilities
        
    def display_vulnerabilities(self, vulnerable):
        """Display vulnerable networks"""
        if not vulnerable:
            return
            
        print("\n\033[91m" + "="*80 + "\033[0m")
        print("\033[91mVULNERABLE NETWORKS\033[0m".center(80))
        print("\033[91m" + "="*80 + "\033[0m")
        
        for net in vulnerable:
            print(f"\n\033[93mESSID: {net['essid']}\033[0m")
            print(f"  BSSID: {net['bssid']}")
            print(f"  Channel: {net['channel']}")
            print(f"  Encryption: {net['encryption']}")
            print("  \033[91mVulnerabilities:\033[0m")
            for vuln in net['vulnerabilities']:
                print(f"    - {vuln}")
                
    def display_secure(self, secure):
        """Display secure networks"""
        if not secure:
            return
            
        print("\n\033[92m" + "="*80 + "\033[0m")
        print("\033[92mSECURE NETWORKS\033[0m".center(80))
        print("\033[92m" + "="*80 + "\033[0m")
        
        for net in secure:
            print(f"\n\033[92mESSID: {net['essid']}\033[0m")
            print(f"  BSSID: {net['bssid']}")
            print(f"  Channel: {net['channel']}")
            print(f"  Encryption: {net['encryption']}")
            
    def display_unknown(self, unknown):
        """Display networks with unknown security"""
        if not unknown:
            return
            
        print("\n\033[93m" + "="*80 + "\033[0m")
        print("\033[93mUNKNOWN SECURITY\033[0m".center(80))
        print("\033[93m" + "="*80 + "\033[0m")
        
        for net in unknown:
            print(f"\n\033[93mESSID: {net['essid']}\033[0m")
            print(f"  BSSID: {net['bssid']}")
            print(f"  Channel: {net['channel']}")
            print(f"  Encryption: {net['encryption']}")
            
    def get_vulnerable_networks(self):
        """Return list of vulnerable networks"""
        return self.vulnerable_networks
