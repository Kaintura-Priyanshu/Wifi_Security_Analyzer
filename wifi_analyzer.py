#!/usr/bin/env python3
"""
WiFi Security Analysis Tool for Kali Linux
"""
import os
import sys
import time
import subprocess
import argparse
from modules.network_scanner import NetworkScanner
from modules.packet_capture import PacketCapture
from modules.deauth_attack import DeauthAttack
from modules.handshake_capture import HandshakeCapture
from modules.security_checker import SecurityChecker

class WiFiSecurityAnalyzer:
    def __init__(self):
        self.interface = None
        self.monitor_interface = None
        self.scanner = NetworkScanner()
        self.packet_capture = PacketCapture()
        self.deauth_attack = DeauthAttack()
        self.handshake_capture = HandshakeCapture()
        self.security_checker = SecurityChecker()
        
    def check_root_privileges(self):
        """Check if the script is running with root privileges"""
        if os.geteuid() != 0:
            print("\033[91m[!] This tool requires root privileges!")
            print("[!] Please run with: sudo python3 wifi_analyzer.py\033[0m")
            sys.exit(1)
            
    def check_dependencies(self):
        """Check if required tools are installed"""
        required_tools = ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng']
        missing_tools = []
        
        for tool in required_tools:
            if subprocess.call(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
                missing_tools.append(tool)
                
        if missing_tools:
            print(f"\033[93m[!] Missing tools: {', '.join(missing_tools)}\033[0m")
            print("[*] Install with: apt-get install aircrack-ng")
            return False
        return True
        
    def list_interfaces(self):
        """List available wireless interfaces"""
        print("\n\033[96m[*] Available wireless interfaces:\033[0m")
        result = subprocess.run(['iwconfig'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        interfaces = []
        
        for line in result.stdout.split('\n'):
            if 'IEEE 802.11' in line:
                interface = line.split()[0]
                interfaces.append(interface)
                print(f"  - {interface}")
                
        if not interfaces:
            print("\033[91m[!] No wireless interfaces found!\033[0m")
            sys.exit(1)
            
        return interfaces
        
    def select_interface(self):
        """Let user select wireless interface"""
        interfaces = self.list_interfaces()
        
        if len(interfaces) == 1:
            self.interface = interfaces[0]
            print(f"\n[*] Using interface: {self.interface}")
            return self.interface
            
        while True:
            try:
                choice = input("\n[?] Select interface number (or enter name): ")
                if choice.isdigit():
                    idx = int(choice) - 1
                    if 0 <= idx < len(interfaces):
                        self.interface = interfaces[idx]
                        break
                elif choice in interfaces:
                    self.interface = choice
                    break
                else:
                    print("\033[91m[!] Invalid selection!\033[0m")
            except KeyboardInterrupt:
                print("\n[*] Exiting...")
                sys.exit(0)
                
        print(f"\n[*] Using interface: {self.interface}")
        return self.interface
        
    def enable_monitor_mode(self):
        """Enable monitor mode on the selected interface"""
        print("\n\033[96m[*] Enabling monitor mode...\033[0m")
        
        # Kill conflicting processes
        subprocess.run(['airmon-ng', 'check', 'kill'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Enable monitor mode
        result = subprocess.run(['airmon-ng', 'start', self.interface], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Find the monitor interface name
        self.monitor_interface = f"{self.interface}mon"
        
        # Check if monitor interface exists
        check = subprocess.run(['iwconfig', self.monitor_interface], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if check.returncode != 0:
            # Try alternative naming
            self.monitor_interface = f"{self.interface}mon"
            print(f"\033[91m[!] Failed to create monitor interface\033[0m")
            print(f"[*] Trying alternative method...")
            
            # Try using iw dev
            subprocess.run(['sudo', 'iw', 'dev', self.interface, 'set', 'type', 'monitor'], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(['sudo', 'ip', 'link', 'set', self.interface, 'up'], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.monitor_interface = self.interface
            
        print(f"\033[92m[+] Monitor mode enabled on: {self.monitor_interface}\033[0m")
        return self.monitor_interface
        
    def scan_networks(self, duration=30):
        """Scan for WiFi networks"""
        print(f"\n\033[96m[*] Scanning for networks (duration: {duration} seconds)...\033[0m")
        networks = self.scanner.scan(self.monitor_interface, duration)
        
        if networks:
            self.scanner.display_networks(networks)
        else:
            print("\033[91m[!] No networks found!\033[0m")
            
        return networks
        
    def perform_security_check(self, networks):
        """Perform security analysis on discovered networks"""
        if not networks:
            print("\033[91m[!] No networks to analyze!\033[0m")
            return
            
        print("\n\033[96m[*] Performing security analysis...\033[0m")
        self.security_checker.analyze_networks(networks)
        
    def capture_handshake(self, bssid, channel):
        """Capture WPA handshake for a specific network"""
        print(f"\n\033[96m[*] Starting handshake capture for {bssid}\033[0m")
        self.handshake_capture.capture(self.monitor_interface, bssid, channel)
        
    def deauth_attack(self, bssid, client=None, count=10):
        """Perform deauthentication attack"""
        print(f"\n\033[96m[*] Starting deauth attack on {bssid}\033[0m")
        self.deauth_attack.attack(self.monitor_interface, bssid, client, count)
        
    def cleanup(self):
        """Clean up and restore network settings"""
        print("\n\033[96m[*] Cleaning up...\033[0m")
        
        if self.monitor_interface and self.monitor_interface != self.interface:
            subprocess.run(['airmon-ng', 'stop', self.monitor_interface], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        subprocess.run(['service', 'NetworkManager', 'restart'], 
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print("\033[92m[+] Cleanup complete!\033[0m")
        
    def main_menu(self):
        """Display main menu and handle user input"""
        while True:
            print("\n" + "="*60)
            print("\033[96mWiFi Security Analysis Tool\033[0m".center(60))
            print("="*60)
            print("1. Scan Networks")
            print("2. Security Analysis")
            print("3. Capture WPA Handshake")
            print("4. Deauth Attack")
            print("5. Full Security Audit")
            print("6. Exit")
            print("="*60)
            
            try:
                choice = input("\n[?] Select option: ")
                
                if choice == '1':
                    networks = self.scan_networks()
                    
                elif choice == '2':
                    networks = self.scan_networks(duration=20)
                    self.perform_security_check(networks)
                    
                elif choice == '3':
                    networks = self.scan_networks(duration=20)
                    if networks:
                        print("\n[*] Enter BSSID of target network:")
                        bssid = input("[?] BSSID: ").strip()
                        channel = input("[?] Channel: ").strip()
                        if bssid and channel:
                            self.capture_handshake(bssid, channel)
                            
                elif choice == '4':
                    networks = self.scan_networks(duration=20)
                    if networks:
                        print("\n[*] Enter BSSID of target network:")
                        bssid = input("[?] BSSID: ").strip()
                        client = input("[?] Client MAC (optional, press Enter to skip): ").strip() or None
                        count = input("[?] Number of deauth packets (default 10): ").strip()
                        count = int(count) if count else 10
                        if bssid:
                            self.deauth_attack(bssid, client, count)
                            
                elif choice == '5':
                    print("\n\033[96m[*] Starting full security audit...\033[0m")
                    networks = self.scan_networks(duration=45)
                    if networks:
                        self.perform_security_check(networks)
                        # Ask if user wants to capture handshake for vulnerable networks
                        vulnerable = self.security_checker.get_vulnerable_networks()
                        if vulnerable:
                            print("\n[*] Vulnerable networks found. Do you want to capture handshake? (y/n)")
                            if input("[?] ").lower() == 'y':
                                for net in vulnerable[:3]:  # Limit to first 3
                                    print(f"\n[*] Capturing handshake for {net['bssid']}...")
                                    self.capture_handshake(net['bssid'], net['channel'])
                    
                elif choice == '6':
                    print("\n[*] Exiting...")
                    self.cleanup()
                    sys.exit(0)
                    
                else:
                    print("\033[91m[!] Invalid option!\033[0m")
                    
            except KeyboardInterrupt:
                print("\n[*] Returning to main menu...")
            except Exception as e:
                print(f"\033[91m[!] Error: {e}\033[0m")
                
    def run(self):
        """Main execution flow"""
        print("\033[96m" + "="*60 + "\033[0m")
        print("\033[96mWiFi Security Analysis Tool\033[0m".center(60))
        print("\033[96m" + "="*60 + "\033[0m")
        
        self.check_root_privileges()
        
        if not self.check_dependencies():
            sys.exit(1)
            
        self.select_interface()
        self.enable_monitor_mode()
        
        try:
            self.main_menu()
        except KeyboardInterrupt:
            print("\n[*] Interrupted by user...")
        finally:
            self.cleanup()

if __name__ == "__main__":
    analyzer = WiFiSecurityAnalyzer()
    analyzer.run()
