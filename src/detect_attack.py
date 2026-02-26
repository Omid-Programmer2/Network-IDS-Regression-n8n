import scapy.all as scapy
from scapy.all import dev_from_index
import time
import requests # For sending alerts to n8n

# --- Configuration ---
# The threshold we calculated in Phase 2
THRESHOLD = 144.83 
# Interface name (You might need to check the exact name in Scapy)
INTERFACE = dev_from_index(14)
# n8n Webhook URL (We will fill this in Phase 4)
N8N_WEBHOOK_URL = "http://localhost:5678/webhook-test/62246be6-37d8-466e-a23e-33c11d8970c9"

packet_count = 0

def process_packet(packet):
    global packet_count
    packet_count += 1

def start_monitoring():
    global packet_count
    print(f"[*] Monitoring started on {INTERFACE}...")
    print(f"[*] Threshold is set to: {THRESHOLD} PPS")
    
    while True:
        packet_count = 0
        # Sniff packets for 1 second
        scapy.sniff(iface=INTERFACE, prn=process_packet, timeout=1, store=0)
        
        current_pps = packet_count
        print(f"Current Traffic: {current_pps} PPS", end='\r')
        
        if current_pps > THRESHOLD:
            print(f"\n[!!!] ANOMALY DETECTED! Traffic: {current_pps} PPS")
            send_alert(current_pps)
            # Small cooldown to avoid spamming alerts
            time.sleep(5)

def send_alert(pps):
    # Prepare the payload with the exact fields you want in Eitaa
    payload = {
        "method": "Linear Regression Model",
        "traffic": pps,
        "threshold": THRESHOLD,
        "status": "Attack Detected",
        "message": "Intrusion detected by Linear Regression Model",
        "student": "Omid",
        "network": "VMware VMnet4"
    }
    
    try:
        response = requests.post(N8N_WEBHOOK_URL, json=payload)
        if response.status_code == 200:
            print(f"[+] Alert sent! Traffic: {pps} PPS")
        else:
            print(f"[!] n8n Error: {response.status_code}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")

if __name__ == "__main__":
    start_monitoring()
