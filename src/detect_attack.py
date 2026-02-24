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
N8N_WEBHOOK_URL = "http://YOUR_N8N_IP:5678/webhook/attack-detected"

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
            time.sleep(2)

def send_alert(pps):
    payload = {
        "status": "Attack Detected",
        "pps_count": pps,
        "threshold": THRESHOLD,
        "message": "Intrusion detected by Linear Regression Model"
    }
    try:
        # We will activate this once n8n is ready
        # requests.post(N8N_WEBHOOK_URL, json=payload)
        print("[+] Alert signal prepared for n8n.")
    except Exception as e:
        print(f"[-] Failed to connect to n8n: {e}")

if __name__ == "__main__":
    start_monitoring()
