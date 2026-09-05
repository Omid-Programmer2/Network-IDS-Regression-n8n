import scapy.all as scapy
from collections import Counter
import subprocess
import platform
import time
import requests
from datetime import datetime

# --- Configuration (Chi-Square Model - Ye & Chen, 2001) ---
# Expected normal traffic distribution based on protocols (baseline 50 packets per second)
EXPECTED_DISTRIBUTION = {
    'TCP': 35.0,   # expect 70% of traffic to be TCP
    'UDP': 10.0,   # expect 20% to be UDP
    'ICMP': 5.0    # expect 10% to be ICMP
}
TOTAL_EXPECTED_PPS = sum(EXPECTED_DISTRIBUTION.values()) # 50.0 PPS

CHI2_THRESHOLD = 179.8      # critical deviation threshold
INTERFACE = "VMware Network Adapter VMnet4"
N8N_WEBHOOK_URL = "http://localhost:5678/webhook-test/62246be6-37d8-466e-a23e-33c11d8970c9"

# Global states
proto_counter = Counter()
ip_counter = Counter()
blocked_ips = set()

def process_packet(packet):
    global proto_counter, ip_counter
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        ip_counter[src_ip] += 1
        
        if packet.haslayer(scapy.TCP):
            proto_counter['TCP'] += 1
        elif packet.haslayer(scapy.UDP):
            proto_counter['UDP'] += 1
        elif packet.haslayer(scapy.ICMP):
            proto_counter['ICMP'] += 1

def block_ip(ip_address):
    if ip_address in blocked_ips:
        print(f"[*] IP {ip_address} is already blocked. Skipping firewall injection.")
        return False

    os_type = platform.system().lower()
    success = False

    try:
        if os_type == "windows":
            cmd_in = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f'name=IDS_AUTO_BLOCK_IN_{ip_address}',
                "dir=in", "action=block", f"remoteip={ip_address}", "profile=any"
            ]
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

    except Exception as e:
        print(f"[-] Error executing firewall command: {e}")

    if success:
        blocked_ips.add(ip_address)
    
    return success

def calculate_multi_chi_square(observed_dist, expected_dist):
    """
    Calculate the actual Chi-Square value according to Ye & Chen (2001) based on the sum of protocol deviations
    """
    total_observed = sum(observed_dist.values())
    
    # if total traffic is less than normal, it's not considered an attack
    if total_observed <= TOTAL_EXPECTED_PPS:
        return 0.0

    chi2_total = 0.0
    for proto, expected_e in expected_dist.items():
        observed_o = observed_dist.get(proto, 0)
        # Chi-Square formula is the sum of deviations squared divided by expected
        chi2_total += ((observed_o - expected_e) ** 2) / expected_e
        
    return chi2_total

def start_monitoring():
    global proto_counter, ip_counter
    print(f"[*] Monitoring started on {INTERFACE} using Multi-Variable Chi-Square Model (Ye & Chen, 2001)...")
    print(f"[*] Baseline Expected Rate: {TOTAL_EXPECTED_PPS} PPS | Chi2 Threshold: {CHI2_THRESHOLD}")

    while True:
        proto_counter.clear()
        ip_counter.clear()

        # sniff for 1 second
        start_time = time.time()
        scapy.sniff(iface=INTERFACE, prn=process_packet, timeout=1, store=0)
        elapsed_time = time.time() - start_time

        # normalize rate based on actual elapsed time
        current_pps = int(sum(proto_counter.values()) / elapsed_time) if elapsed_time > 0 else 0
        chi2_score = calculate_multi_chi_square(proto_counter, EXPECTED_DISTRIBUTION)

        print(f"Current Traffic: {current_pps} PPS | Chi2 Score: {chi2_score:.2f}    ", end='\r')

        if chi2_score > CHI2_THRESHOLD:
            attack_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[!!!] ANOMALY DETECTED via Chi-Square at [{attack_time}]! Score: {chi2_score:.2f} (Traffic: {current_pps} PPS)")
            
            attacker_ip = "Unknown"
            if ip_counter:
                attacker_ip = ip_counter.most_common(1)[0][0]
                print(f"[!] Attacker IP identified: {attacker_ip}")
                block_ip(attacker_ip)

            send_alert(current_pps, chi2_score, attacker_ip)
            time.sleep(2)

def send_alert(pps, chi2_val, attacker_ip):
    payload = {
        "method": "Chi-Square Test Model (Ye & Chen, 2001)",
        "traffic": pps,
        "chi2_score": round(chi2_val, 2),
        "threshold": CHI2_THRESHOLD,
        "status": "Attack Detected & Blocked",
        "message": "Intrusion detected by Chi-Square Statistic Model",
        "student": "Omid",
        "network": "VMware VMnet4",
        "blocked_ip": attacker_ip,
        "action": "Active Response - Firewall Block"
    }

    try:
        response = requests.post(N8N_WEBHOOK_URL, json=payload, timeout=2)
        if response.status_code == 200:
            print(f"[+] Alert sent to n8n! Traffic: {pps} PPS | Chi2: {chi2_val:.2f} | Target IP: {attacker_ip}")
        else:
            print(f"[!] n8n Error: {response.status_code}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    start_monitoring()