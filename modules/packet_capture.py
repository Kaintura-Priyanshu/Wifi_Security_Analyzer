#!/usr/bin/env python3
"""
Packet Capture Module
"""

import subprocess
import time
import os
from datetime import datetime

class PacketCapture:
    def __init__(self):
        self.capture_process = None
        self.capture_file = None
        
    def start_capture(self, interface, bssid, channel, duration=60):
        """Start packet capture on specific channel"""
        self.capture_file = f"/tmp/capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        try:
            # Set channel
            subprocess.run(['sudo', 'iw', 'dev', interface, 'set', 'channel', channel], 
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Start airodump-ng
            cmd = [
                'airodump-ng',
                interface,
                '--bssid', bssid,
                '--channel', channel,
                '--write', self.capture_file,
                '--output-format', 'cap'
            ]
            
            self.capture_process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"\033[92m[+] Packet capture started on channel {channel}\033[0m")
            
            # Let it run for specified duration
            time.sleep(duration)
            self.stop_capture()
            
            return f"{self.capture_file}-01.cap"
            
        except Exception as e:
            print(f"\033[91m[!] Error during capture: {e}\033[0m")
            return None
            
    def stop_capture(self):
        """Stop packet capture process"""
        if self.capture_process:
            self.capture_process.terminate()
            time.sleep(2)
            self.capture_process = None
            print("\033[92m[+] Packet capture stopped\033[0m")
