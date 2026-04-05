import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from prometheus_client import start_http_server, Counter, Gauge
import time
import mysql.connector
import subprocess

# Database settings
db_config = {
    "host": "127.0.0.1",
    "port": "3306",
    "user": "nilesh",
    "password": "1234", 
    "database": "cyber_logs"
}

# --- NAYA: 2. AWS DB Config yahan add karein ---
aws_db_config = {
    "host": "cyber-ids-db.cnaywaeomc7q.ap-south-1.rds.amazonaws.com",  # <-- Apna AWS URL daalein
    "port": "3306",
    "user": "admin",                            # <-- AWS Username
    "password": "Backup.db$2026",           # <-- AWS Password
    "database": "cyber_logs"
}

# --- 1. PROMETHEUS CONFIG (Data Expose karna) ---
# Ye 'Counters' Grafana me dikhenge
TOTAL_PACKETS = Counter('network_packets_total', 'Total Packets Scanned')
ANOMALIES = Counter('network_anomalies_total', 'Total Anomalies Detected')
PACKET_SIZE = Gauge('network_packet_size_bytes', 'Real-time Packet Size')

# Server start karo Port 8000 par taaki Prometheus isse padh sake
print("🌍 Starting Metrics Server on Port 8000...")
start_http_server(8000)

# --- 2. LOAD AI MODEL ---
print("🔄 Loading AI Model...")
try:
    model = joblib.load('model.pkl') # Make sure ye naam sahi ho
    le_proto = joblib.load('le_proto.pkl')
    le_service = joblib.load('le_service.pkl')
    print("✅ Model Loaded!")
except:
    model = None
    print("⚠️ Model nahi mila, Basic Monitoring Mode ON.")

# Helpers
port_map = {80: 'http', 443: 'http', 22: 'ssh', 21: 'ftp', 3306: 'sql'}

# --- NAYA: 3. IPS Function yahan add karein ---
def block_ip(ip_address):
    # Local loopback ya safe IPs ko block mat karna
    if ip_address == "127.0.0.1" or ip_address.startswith("192.168."):
        return
    try:
        print(f"🚫 IPS ACTION: Blocking {ip_address} via iptables...")
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
    except Exception as e:
        print(f"❌ IPS Error: {e}")

def process_packet(packet):
    if not packet.haslayer(IP): return

    # 1. Update Metrics (Grafana ke liye)
    TOTAL_PACKETS.inc()       # Count badhao
    size = len(packet)
    PACKET_SIZE.set(size)     # Speedometer update karo
    
    src_ip = packet[IP].src

    if model is None: return

    # 2. AI Check
    try:
        proto = 'tcp'
        port = 0
        if packet.haslayer(TCP): port = packet[TCP].dport
        elif packet.haslayer(UDP): 
            proto = 'udp'
            port = packet[UDP].dport
        
        service = port_map.get(port, 'other')

        # Encoding
        p_val = 0
        if proto in le_proto.classes_: p_val = le_proto.transform([proto])[0]
        
        s_val = 0
        if service in le_service.classes_: s_val = le_service.transform([service])[0]
        else: s_val = le_service.transform(['other'])[0]

        features = pd.DataFrame([[p_val, s_val, size]], columns=['protocol_type', 'service', 'src_bytes'])
        pred = model.predict(features)

        if pred[0] == -1 or size > 2000:
        # Ye line 'if' se thodi aage honi chahiye
            ANOMALIES.inc()
            print(f"🚨 ANOMALY: {src_ip} | Size: {size}")
            
        # --- NAYA: 4. IPS Trigger karein ---
        block_ip(src_ip)
        
        # SQL query aur values common rakh lete hain
        sql = "INSERT INTO attacks (ip_address, packet_size, status) VALUES (%s, %s, %s)"
        val = (src_ip, size, "High Risk Attack")

        # --- NAYA: 5. LOCAL DB me save ---
        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute(sql, val)
            conn.commit()
            print("💾 Log Saved Local!")
            conn.close()
        except Exception as e:
            print(f"❌ Local DB Error: {e}")

        # --- NAYA: 6. AWS DB me save ---
        try:
            conn_aws = mysql.connector.connect(**aws_db_config)
            cursor_aws = conn_aws.cursor()
            cursor_aws.execute(sql, val)
            conn_aws.commit()
            print("☁️ Log Saved to AWS!")
            conn_aws.close()
        except Exception as e:
            print(f"⚠️ AWS Error (Skipped): {e}")

        else:
            print(f"✅ Normal: {src_ip}", end="\r")

    except Exception as e:
        pass

print("📡 Sniffer Started! Metrics available at http://localhost:8000")
sniff(iface="lo",filter="ip", prn=process_packet, count=0)

