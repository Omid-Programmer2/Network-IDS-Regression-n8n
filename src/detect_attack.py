import scapy.all as scapy
from collections import Counter
import subprocess
import platform
import time
import requests
from datetime import datetime

# --- Configuration ---
THRESHOLD = 144.83
INTERFACE = "VMware Network Adapter VMnet4"
N8N_WEBHOOK_URL = "http://localhost:5678/webhook-test/62246be6-37d8-466e-a23e-33c11d8970c9"

# Global states
packet_count = 0
ip_counter = Counter()
blocked_ips = set()

def process_packet(packet):
    global packet_count, ip_counter
    packet_count += 1
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        ip_counter[src_ip] += 1

def block_ip(ip_address):
    if ip_address in blocked_ips:
        print(f"[*] IP {ip_address} is already blocked. Skipping firewall injection.")
        return False

    os_type = platform.system().lower()
    success = False

    try:
        if os_type == "windows":
            # 1. Inbound Block
            cmd_in = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f'name=IDS_AUTO_BLOCK_IN_{ip_address}',
                "dir=in", "action=block", f"remoteip={ip_address}", "profile=any"
            ]
            # 2. Outbound Block
            cmd_out = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f'name=IDS_AUTO_BLOCK_OUT_{ip_address}',
                "dir=out", "action=block", f"remoteip={ip_address}", "profile=any"
            ]
            
            res1 = subprocess.run(cmd_in, capture_output=True, text=True)
            res2 = subprocess.run(cmd_out, capture_output=True, text=True)
            
            if res1.returncode == 0 and res2.returncode == 0:
                print(f"[+] Successfully blocked ALL traffic for IP {ip_address} in Windows Firewall.")
                success = True

        elif os_type == "linux":
            cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"[+] Successfully blocked IP {ip_address} in iptables.")
                success = True
            else:
                print(f"[-] Failed to block IP {ip_address}: {result.stderr}")

    except Exception as e:
        print(f"[-] Error executing firewall command: {e}")

    if success:
        blocked_ips.add(ip_address)
    
    return success

def start_monitoring():
    global packet_count, ip_counter
    print(f"[*] Monitoring started on {INTERFACE}...")
    print(f"[*] Threshold is set to: {THRESHOLD} PPS")

    while True:
        packet_count = 0
        ip_counter.clear()

        # Sniff packets for 1 second
        scapy.sniff(iface=INTERFACE, prn=process_packet, timeout=1, store=0)

        current_pps = packet_count
        print(f"Current Traffic: {current_pps} PPS", end='\r')

        if current_pps > THRESHOLD:
            # Capture accurate system time upon attack detection
            attack_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            print(f"\n[!!!] ANOMALY DETECTED at [{attack_time}]! Traffic: {current_pps} PPS")
            
            attacker_ip = "Unknown"
            if ip_counter:
                attacker_ip = ip_counter.most_common(1)[0][0]
                print(f"[!] Attacker IP identified: {attacker_ip}")
                
                # Active response execution
                block_ip(attacker_ip)

            send_alert(current_pps, attacker_ip)
            time.sleep(5)

def send_alert(pps, attacker_ip):
    payload = {
        "method": "Linear Regression Model",
        "traffic": pps,
        "threshold": THRESHOLD,
        "status": "Attack Detected & Blocked",
        "message": "Intrusion detected by Linear Regression Model",
        "student": "Omid",
        "network": "VMware VMnet4",
        "blocked_ip": attacker_ip,
        "action": "Active Response - Firewall Block"
    }

    try:
        response = requests.post(N8N_WEBHOOK_URL, json=payload)
        if response.status_code == 200:
            print(f"[+] Alert sent to n8n! Traffic: {pps} PPS | Target IP: {attacker_ip}")
        else:
            print(f"[!] n8n Error: {response.status_code}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    start_monitoring()