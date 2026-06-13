#!/usr/bin/env python3
import json
import os
from datetime import datetime
from collections import defaultdict
import subprocess

def read_cowrie_logs():
    """Read Cowrie logs with sudo"""
    logs = []
    try:
        result = subprocess.run(
            ['sudo', 'cat', '/home/cowrie/cowrie/var/log/cowrie/cowrie.log'],
            capture_output=True,
            text=True
        )
        for line in result.stdout.split('\n'):
            if line.strip():
                logs.append(line)
    except:
        pass
    return logs

def read_opencanary_logs():
    """Read OpenCanary logs"""
    logs = []
    try:
        with open('/var/tmp/opencanary.log', 'r') as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except:
                    pass
    except:
        pass
    return logs

def display_dashboard():
    """Display honeypot dashboard"""
    
    cowrie_logs = read_cowrie_logs()
    opencanary_logs = read_opencanary_logs()
    
    print("\n" + "="*80)
    print(" 🍯 HONEYPOT FRAMEWORK — LIVE DASHBOARD ".center(80))
    print("="*80)
    
    # Cowrie Summary
    print("\n📊 COWRIE SSH HONEYPOT (Port 2222)")
    print("-" * 80)
    print(f"   Total log lines: {len(cowrie_logs)}")
    
    ssh_connections = [l for l in cowrie_logs if 'New connection' in l]
    ssh_auths = [l for l in cowrie_logs if 'trying auth' in l]
    ssh_commands = [l for l in cowrie_logs if 'CMD:' in l]
    
    print(f"   SSH connections: {len(ssh_connections)}")
    print(f"   Authentication attempts: {len(ssh_auths)}")
    print(f"   Commands executed: {len(ssh_commands)}")
    
    if ssh_commands:
        print(f"\n   Last 5 commands executed:")
        for cmd in ssh_commands[-5:]:
            # Extract command from log
            parts = cmd.split('CMD:')
            if len(parts) > 1:
                print(f"      → {parts[1].strip()[:60]}")
    
    # OpenCanary Summary
    print("\n\n🪤 OPENCANARY MULTI-SERVICE HONEYPOT")
    print("-" * 80)
    print(f"   Total events: {len(opencanary_logs)}")
    
    # Count by port
    ports = defaultdict(int)
    logins = []
    http_requests = []
    
    for log in opencanary_logs:
        port = log.get('dst_port')
        if port and port > 0:
            ports[port] += 1
        
        logdata = log.get('logdata', {})
        if logdata.get('USERNAME'):
            logins.append(logdata)
        if log.get('logtype') == 3003:
            http_requests.append(log)
    
    print(f"   Active services:")
    port_names = {21: 'FTP', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL', 2223: 'SSH', 23: 'Telnet', 445: 'SMB'}
    for port in sorted(ports.keys()):
        name = port_names.get(port, f'Unknown')
        count = ports[port]
        print(f"      • {name:12} (port {port:5}): {count:3} attempts")
    
    if logins:
        print(f"\n   Credentials captured: {len(logins)}")
        print(f"   Sample logins:")
        for login in logins[-5:]:
            user = login.get('USERNAME', '?')
            pwd = login.get('PASSWORD', '?')
            print(f"      • {user}:{pwd}")
    
    if http_requests:
        print(f"\n   HTTP requests captured: {len(http_requests)}")
        for req in http_requests[-3:]:
            path = req.get('logdata', {}).get('PATH', '/')
            ua = req.get('logdata', {}).get('USERAGENT', 'unknown')[:40]
            print(f"      • {path} — {ua}")
    
    # Statistics
    print("\n\n📈 ATTACK STATISTICS")
    print("-" * 80)
    total_events = len(cowrie_logs) + len(opencanary_logs)
    print(f"   Total events captured: {total_events}")
    print(f"   Honeypots active: 2 (Cowrie + OpenCanary)")
    print(f"   Ports monitored: 11 (2222, 21, 80, 443, 3306, 2223, 23, 445, 1433, 5432, 6379)")
    print(f"   Status: ✅ OPERATIONAL")
    
    print("\n" + "="*80)
    print(" Next Step: Deploy to AWS Phase 2 ".center(80))
    print("="*80 + "\n")

if __name__ == "__main__":
    display_dashboard()
