import scapy.all as scapy
import pandas as pd
import numpy as np
from scipy.stats import poisson
from sklearn.naive_bayes import GaussianNB
import requests
import time
import sys
import warnings

# Disable unnecessary warning messages to keep the console clean
warnings.filterwarnings("ignore")

# ==========================================
# CONFIGURATION
# ==========================================
WIN10_IP = "192.168.164.1" 
WEBHOOK_URL = f"http://{WIN10_IP}:5678/webhook-test/attack-alert"
INTERFACE = "Local Area Connection" 
MONITOR_WINDOW = 5.0 # Window size for analysis

# ==========================================
# PHASE 1: BRAIN INITIALIZATION
# ==========================================
def initialize_ids_brain():
    print("[*] Initializing Machine Learning Brain...")
    try:
        # Load traffic data from CSV files
        normal_df = pd.read_csv("normal_traffic_analysis.csv")
        attack_df = pd.read_csv("attack_traffic_analysis.csv")
        
        normal_df['label'] = 0
        attack_df['label'] = 1
        
        full_data = pd.concat([normal_df, attack_df], ignore_index=True)
        
        X = full_data.drop(["filename", "label"], axis=1)
        y = full_data["label"]
        
        model = GaussianNB()
        model.fit(X, y)
        print("[SUCCESS] Brain is ready.")
        return model
    except Exception as e:
        print(f"[ERROR] Failed to load training data: {e}")
        sys.exit(1)

# ==========================================
# PHASE 2: SMART FEATURE EXTRACTION
# ==========================================
def extract_live_features(packets, duration=5.0):
    total_pkt = len(packets)
    if total_pkt < 20: return None
    
    # Calculate Average Packet Size (Separates large login packets from small exploit chunks)
    avg_size = np.mean([len(p) for p in packets])
    
    start_time = float(packets[0].time)
    timestamps = [float(p.time) - start_time for p in packets]
    bins = np.arange(0, duration + 1, 1)
    pps_counts, _ = np.histogram(timestamps, bins=bins)
    
    mean_rate_lambda = np.mean(pps_counts)
    
    # Precise anomaly detection using Poisson survival function
    anomalies = [c for c in pps_counts if poisson.sf(c, mean_rate_lambda) < 0.001]
    anomaly_count = len(anomalies)
    
    # Decision Logic: High intensity OR Sustained small-packet activity
    is_suspicious = False
    if mean_rate_lambda > 35: 
        is_suspicious = True
    elif anomaly_count >= 2 and avg_size < 120: 
        is_suspicious = True
        
    if not is_suspicious: return None

    attack_score = (anomaly_count / len(pps_counts)) * 100
    return np.array([[mean_rate_lambda, duration, anomaly_count, attack_score]])

# ==========================================
# PHASE 3: MONITORING & ALERTING
# ==========================================
def run_realtime_ids():
    clf = initialize_ids_brain()
    print(f"[*] Intelligent IDS Active on {INTERFACE}...")
    print("-" * 50)

    while True:
        try:
            # Capture live TCP traffic on port 445 (SMB)
            sniffed_packets = scapy.sniff(iface=INTERFACE, filter="tcp port 445", timeout=MONITOR_WINDOW)
            
            # Extract features using the smart logic (Size + Rate)
            live_features = extract_live_features(sniffed_packets, duration=MONITOR_WINDOW)
            
            if live_features is not None:
                prediction = clf.predict(live_features)[0]
                confidence = clf.predict_proba(live_features)[0][1]
                
                # Logic: Only alert if ML is highly confident
                if prediction == 1 and confidence > 0.92:
                    print(f"!!! ATTACK DETECTED !!! Confidence: {confidence*100:.1f}%")
                    
                    # EXACT PAYLOAD FROM YOUR ORIGINAL CODE
                    alert_payload = {
                        "status": "VULNERABILITY EXPLOITED",
                        "event": "Intrusion Detected",
                        "target_os": "Windows 7 x64",
                        "vulnerability": "MS17-010 (EternalBlue)",
                        "probability": f"{confidence*100:.2f}%",
                        "alert_type": "Machine Learning (Naive Bayes)",
                        "student": "Omid",
                        "professor": "Dr.Rahseparfard",
                        "timestamp": time.ctime()
                    }
                    
                    try:
                        response = requests.post(WEBHOOK_URL, json=alert_payload, timeout=10)
                        print(f"[+] n8n Response: {response.status_code}")
                    except Exception as e:
                        print(f"[!] Send Failed: {e}")
                else:
                    print(f"Log: Traffic analyzed - Clean (Rate: {live_features[0][0]:.2f})")
            else:
                print("Log: Normal SMB activity.")

        except KeyboardInterrupt:
            print("\n[*] Stopping IDS...")
            break
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    run_realtime_ids()