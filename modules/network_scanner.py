#!/usr/bin/env python3
"""
Network Scanner Module
"""
import os
import time
import subprocess
import re
import json
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.networks = []
        
    def scan(self, interface, duration=30):
        """Scan for WiFi networks using airodump-ng"""
        temp_file = f"/tmp/wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Start airodump-ng
            cmd = [
                'airodump-ng',
                interface,
                '--write', temp_file,
                '--output-format', 'csv',
                '--band', 'abg'
            ]
            
            print(f"\n[*] Scanning for {duration} seconds...")
            process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(duration)
            process.terminate()
            time.sleep(2)
            
            # Parse results
            networks = self.parse_airodump_output(f"{temp_file}-01.csv")
            
            # Clean up temp files
            subprocess.run(['rm', '-f', f"{temp_file}-01.csv"], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            return networks
            
        except Exception as e:
            print(f"\033[91m[!] Error during scan: {e}\033[0m")
            return []
            
    def parse_airodump_output(self, csv_file):
        """Parse airodump-ng CSV output"""
        networks = []
        
        if not os.path.exists(csv_file):
            return networks
            
        try:
            with open(csv_file, 'r') as f:
                lines = f.readlines()
                
            # Find where networks section starts
            network_start = False
            for i, line in enumerate(lines):
                if 'BSSID' in line and 'ESSID' in line:
                    network_start = True
                    continue
                if network_start and line.strip():
                    parts = re.split(',', line.strip())
                    if len(parts) >= 14:
                        bssid = parts[0].strip()
                        channel = parts[3].strip()
                        encryption = parts[5].strip()
                        essid = parts[13].strip()
                        
                        # Skip empty ESSID
                        if essid and essid != '':
                            networks.append({
                                'bssid': bssid,
                                'channel': channel,
                                'encryption': encryption,
                                'essid': essid,
                                'wpa': 'WPA' in encryption or 'WPA2' in encryption,
                                'wep': 'WEP' in encryption,
                                'open': 'OPN' in encryption
                            })
                        
        except Exception as e:
            print(f"\033[91m[!] Error parsing file: {e}\033[0m")
            
        return networks
        
    def display_networks(self, networks):
        """Display discovered networks in a formatted table"""
        if not networks:
            print("\n\033[93m[!] No networks found.\033[0m")
            return
            
        print("\n\033[96m" + "="*100 + "\033[0m")
        print(f"\033[96m{'BSSID':<20} {'ESSID':<30} {'Channel':<10} {'Encryption':<20} {'Security'}\033[0m")
        print("-"*100)
        
        for net in networks:
            security = self.get_security_status(net)
            color = self.get_security_color(security)
            print(f"{net['bssid']:<20} {net['essid']:<30} {net['channel']:<10} {net['encryption']:<20} {color}{security}\033[0m")
            
        print(f"\n\033[92m[+] Found {len(networks)} networks\033[0m")
        
    def get_security_status(self, network):
        """Determine security status of a network"""
        if network.get('wep'):
            return "WEP (Insecure)"
        elif network.get('wpa'):
            if 'WPA2' in network.get('encryption', ''):
                return "WPA2 (Good)"
            else:
                return "WPA (Weak)"
        elif network.get('open'):
            return "Open (Insecure)"
        else:
            return "Unknown"
            
    def get_security_color(self, status):
        """Get color code based on security status"""
        if "Insecure" in status:
            return "\033[91m"  # Red
        elif "Weak" in status:
            return "\033[93m"  # Yellow
        elif "Good" in status:
            return "\033[92m"  # Green
        else:
            return "\033[0m"   # Default
