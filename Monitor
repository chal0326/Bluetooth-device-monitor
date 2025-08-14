#!/usr/bin/env python3
"""
Comprehensive Network and Bluetooth Device Monitor
Runs on Raspberry Pi to correlate network and Bluetooth devices
"""

import subprocess
import time
import json
import sqlite3
import re
import threading
from datetime import datetime
import logging
from dataclasses import dataclass
from typing import Dict, List, Set, Optional

@dataclass
class Device:
    mac_address: str
    device_type: str  # 'wifi', 'bluetooth', 'network'
    name: str
    manufacturer: str
    first_seen: datetime
    last_seen: datetime
    ip_address: Optional[str] = None
    signal_strength: Optional[int] = None
    device_class: Optional[str] = None

class DeviceMonitor:
    def __init__(self, db_path="device_monitor.db"):
        self.db_path = db_path
        self.devices = {}
        self.correlation_patterns = {}
        self.setup_database()
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('device_monitor.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def setup_database(self):
        """Initialize SQLite database for device tracking"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT UNIQUE,
                device_type TEXT,
                name TEXT,
                manufacturer TEXT,
                ip_address TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                signal_strength INTEGER,
                device_class TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wifi_mac TEXT,
                bluetooth_mac TEXT,
                confidence_score REAL,
                correlation_method TEXT,
                timestamp TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def get_oui_manufacturer(self, mac_address):
        """Get manufacturer from MAC OUI"""
        oui = mac_address.upper().replace(':', '').replace('-', '')[:6]
        # You can download OUI database or use online API
        # For now, basic mapping
        oui_map = {
            '001122': 'Apple',
            '001A2B': 'Samsung',
            '00E04C': 'Realtek',
            # Add more as needed
        }
        return oui_map.get(oui, 'Unknown')
        
    def scan_network_devices(self):
        """Scan for devices on the local network"""
        try:
            # ARP scan for active devices
            result = subprocess.run(['arp-scan', '-l'], 
                                  capture_output=True, text=True, timeout=30)
            
            devices = []
            for line in result.stdout.split('\n'):
                if re.match(r'^\d+\.\d+\.\d+\.\d+', line):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0]
                        mac = parts[1].upper()
                        manufacturer = ' '.join(parts[2:]) if len(parts) > 2 else self.get_oui_manufacturer(mac)
                        
                        device = Device(
                            mac_address=mac,
                            device_type='network',
                            name=f"Network-{ip}",
                            manufacturer=manufacturer,
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            ip_address=ip
                        )
                        devices.append(device)
                        
            # Try to get hostnames
            for device in devices:
                try:
                    hostname_result = subprocess.run(['nslookup', device.ip_address], 
                                                   capture_output=True, text=True, timeout=5)
                    if 'name =' in hostname_result.stdout:
                        hostname = hostname_result.stdout.split('name = ')[1].split('.')[0]
                        device.name = hostname
                except:
                    pass
                    
            return devices
            
        except Exception as e:
            self.logger.error(f"Network scan error: {e}")
            return []
            
    def scan_bluetooth_devices(self):
        """Scan for Bluetooth devices"""
        try:
            # Use bluetoothctl for scanning
            subprocess.run(['bluetoothctl', 'scan', 'on'], timeout=2)
            time.sleep(10)  # Scan for 10 seconds
            
            result = subprocess.run(['bluetoothctl', 'devices'], 
                                  capture_output=True, text=True)
            
            devices = []
            for line in result.stdout.split('\n'):
                if line.startswith('Device '):
                    parts = line.split()
                    if len(parts) >= 3:
                        mac = parts[1].upper()
                        name = ' '.join(parts[2:])
                        
                        device = Device(
                            mac_address=mac,
                            device_type='bluetooth',
                            name=name,
                            manufacturer=self.get_oui_manufacturer(mac),
                            first_seen=datetime.now(),
                            last_seen=datetime.now()
                        )
                        devices.append(device)
                        
            subprocess.run(['bluetoothctl', 'scan', 'off'])
            return devices
            
        except Exception as e:
            self.logger.error(f"Bluetooth scan error: {e}")
            return []
            
    def scan_wifi_devices(self):
        """Scan for WiFi devices (requires monitor mode)"""
        try:
            # This requires monitor mode setup
            # Using iwlist as simpler alternative
            result = subprocess.run(['iwlist', 'wlan0', 'scan'], 
                                  capture_output=True, text=True)
            
            devices = []
            current_device = {}
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if 'Address:' in line:
                    if current_device:
                        device = Device(
                            mac_address=current_device.get('mac', '').upper(),
                            device_type='wifi',
                            name=current_device.get('name', 'Unknown'),
                            manufacturer=self.get_oui_manufacturer(current_device.get('mac', '')),
                            first_seen=datetime.now(),
                            last_seen=datetime.now(),
                            signal_strength=current_device.get('signal')
                        )
                        devices.append(device)
                    
                    current_device = {'mac': line.split('Address: ')[1]}
                    
                elif 'ESSID:' in line:
                    essid = line.split('ESSID:')[1].strip('"')
                    current_device['name'] = essid if essid else 'Hidden'
                    
                elif 'Signal level=' in line:
                    signal = re.search(r'Signal level=(-?\d+)', line)
                    if signal:
                        current_device['signal'] = int(signal.group(1))
                        
            return devices
            
        except Exception as e:
            self.logger.error(f"WiFi scan error: {e}")
            return []
            
    def correlate_devices(self, network_devices, bluetooth_devices, wifi_devices):
        """Attempt to correlate devices across different interfaces"""
        correlations = []
        
        all_devices = network_devices + bluetooth_devices + wifi_devices
        
        for i, device1 in enumerate(all_devices):
            for device2 in all_devices[i+1:]:
                if device1.device_type != device2.device_type:
                    confidence = self.calculate_correlation_confidence(device1, device2)
                    if confidence > 0.5:  # Threshold for correlation
                        correlations.append({
                            'device1': device1,
                            'device2': device2,
                            'confidence': confidence,
                            'method': self.get_correlation_method(device1, device2)
                        })
                        
        return correlations
        
    def calculate_correlation_confidence(self, device1, device2):
        """Calculate confidence score for device correlation"""
        confidence = 0.0
        
        # Check OUI similarity (same manufacturer)
        if device1.manufacturer == device2.manufacturer and device1.manufacturer != 'Unknown':
            confidence += 0.3
            
        # Check name similarity
        if device1.name and device2.name:
            name1 = device1.name.lower().replace(' ', '').replace('-', '').replace('_', '')
            name2 = device2.name.lower().replace(' ', '').replace('-', '').replace('_', '')
            
            if name1 in name2 or name2 in name1:
                confidence += 0.4
            elif any(word in name2 for word in name1.split() if len(word) > 3):
                confidence += 0.2
                
        # Check MAC address patterns (sequential allocation)
        mac1_int = int(device1.mac_address.replace(':', ''), 16)
        mac2_int = int(device2.mac_address.replace(':', ''), 16)
        mac_diff = abs(mac1_int - mac2_int)
        
        if mac_diff < 10:  # Very close MAC addresses
            confidence += 0.4
        elif mac_diff < 100:  # Moderately close
            confidence += 0.2
            
        return min(confidence, 1.0)
        
    def get_correlation_method(self, device1, device2):
        """Determine how devices were correlated"""
        methods = []
        
        if device1.manufacturer == device2.manufacturer:
            methods.append('manufacturer_match')
            
        if device1.name and device2.name:
            name1 = device1.name.lower()
            name2 = device2.name.lower()
            if name1 in name2 or name2 in name1:
                methods.append('name_similarity')
                
        mac1_int = int(device1.mac_address.replace(':', ''), 16)
        mac2_int = int(device2.mac_address.replace(':', ''), 16)
        if abs(mac1_int - mac2_int) < 100:
            methods.append('mac_proximity')
            
        return ','.join(methods)
        
    def save_devices_to_db(self, devices):
        """Save discovered devices to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for device in devices:
            cursor.execute('''
                INSERT OR REPLACE INTO devices 
                (mac_address, device_type, name, manufacturer, ip_address, 
                 first_seen, last_seen, signal_strength, device_class)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device.mac_address,
                device.device_type,
                device.name,
                device.manufacturer,
                device.ip_address,
                device.first_seen,
                device.last_seen,
                device.signal_strength,
                device.device_class
            ))
            
        conn.commit()
        conn.close()
        
    def save_correlations_to_db(self, correlations):
        """Save device correlations to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for corr in correlations:
            cursor.execute('''
                INSERT INTO correlations 
                (wifi_mac, bluetooth_mac, confidence_score, correlation_method, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                corr['device1'].mac_address,
                corr['device2'].mac_address,
                corr['confidence'],
                corr['method'],
                datetime.now()
            ))
            
        conn.commit()
        conn.close()
        
    def run_scan_cycle(self):
        """Run one complete scan cycle"""
        self.logger.info("Starting scan cycle...")
        
        # Scan all interfaces
        network_devices = self.scan_network_devices()
        bluetooth_devices = self.scan_bluetooth_devices()
        wifi_devices = self.scan_wifi_devices()
        
        self.logger.info(f"Found: {len(network_devices)} network, "
                        f"{len(bluetooth_devices)} bluetooth, "
                        f"{len(wifi_devices)} wifi devices")
        
        # Correlate devices
        correlations = self.correlate_devices(network_devices, bluetooth_devices, wifi_devices)
        
        # Save to database
        all_devices = network_devices + bluetooth_devices + wifi_devices
        self.save_devices_to_db(all_devices)
        self.save_correlations_to_db(correlations)
        
        # Log high-confidence correlations
        for corr in correlations:
            if corr['confidence'] > 0.7:
                self.logger.info(f"High confidence correlation: "
                               f"{corr['device1'].name} ({corr['device1'].mac_address}) <-> "
                               f"{corr['device2'].name} ({corr['device2'].mac_address}) "
                               f"[{corr['confidence']:.2f}]")
                
        return len(all_devices), len(correlations)
        
    def run_continuous_monitoring(self, scan_interval=300):
        """Run continuous monitoring with specified interval"""
        self.logger.info(f"Starting continuous monitoring (interval: {scan_interval}s)")
        
        while True:
            try:
                device_count, correlation_count = self.run_scan_cycle()
                self.logger.info(f"Scan complete: {device_count} devices, "
                               f"{correlation_count} correlations")
                time.sleep(scan_interval)
                
            except KeyboardInterrupt:
                self.logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                self.logger.error(f"Error during scan cycle: {e}")
                time.sleep(60)  # Wait before retrying

if __name__ == "__main__":
    monitor = DeviceMonitor()
    
    # Run single scan
    # monitor.run_scan_cycle()
    
    # Run continuous monitoring (scan every 5 minutes)
    monitor.run_continuous_monitoring(scan_interval=300)
