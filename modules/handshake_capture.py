#!/usr/bin/env python3
"""
Handshake Capture Module
"""
import subprocess
import time
import os

class HandshakeCapture:
    def __init__(self):
        self.capture_process = None
        self.capture_file = None
        
    def capture(self, interface, bssid, channel, duration=60):
        """Capture WPA handshake"""
        try:
            # Set channel
            subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'channel', channel], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Start airodump-ng to capture handshake
            self.capture_file = f"/tmp/handshake_{bssid.replace(':', '')}"
            
            cmd = [
                'airodump-ng',
                interface,
                '--bssid', bssid,
                '--channel', channel,
                '--write', self.capture_file,
                '--output-format', 'cap'
            ]
            
            print("\033[93m[*] Capturing handshake...")
            print("[*] This may take several minutes.")
            print("[*] Wait for 'WPA handshake' message in output...")
            print(f"[*] Target: {bssid} on channel {channel}\033[0m")
            
            # Start capture
            self.capture_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Monitor for handshake
            start_time = time.time()
            handshake_captured = False
            
            while time.time() - start_time < duration:
                line = self.capture_process.stdout.readline()
                if line and b'WPA handshake' in line:
                    handshake_captured = True
                    print("\033[92m[+] Handshake captured successfully!\033[0m")
                    break
                    
            if not handshake_captured:
                print("\033[91m[!] Handshake not captured. Try again with more time or deauth attack.\033[0m")
                
            # Stop capture
            self.capture_process.terminate()
            time.sleep(2)
            
            # Check if handshake file exists
            cap_file = f"{self.capture_file}-01.cap"
            if os.path.exists(cap_file):
                print(f"\033[92m[+] Capture saved to: {cap_file}\033[0m")
                return cap_file
            else:
                print("\033[91m[!] No capture file created\033[0m")
                return None
                
        except Exception as e:
            print(f"\033[91m[!] Error during handshake capture: {e}\033[0m")
            return None
