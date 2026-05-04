# AI Powered Network Traffic Analyzer With Anomaly Detection and AWS Based Logging

## Project Overview
This project implements a proactive Intrusion Prevention System (IPS) that uses the **Isolation Forest** algorithm to detect network anomalies in real-time. It is designed to automatically mitigate threats by blocking malicious IPs using `iptables` and syncing logs to **AWS RDS**.

## Tech Stack
- **Languages:** Python (Scapy, Scikit-learn)
- **Infrastructure:** Docker (Containerized)
- **Cloud:** AWS RDS (MySQL)
- **Monitoring:** Prometheus & Grafana

## File Descriptions
- `sniffer.py`: Captures live network traffic and extracts features.
- `train.py`: Script to train the Isolation Forest model using the `KDDTest+.txt` dataset.
- `model.pkl`: The serialized pre-trained ML model.
- `prometheus.yml`: Configuration for metric collection and monitoring.
- `attack.py`: Script used for testing/simulating network anomalies.

## Setup Instructions
1. Build the Docker container: `docker build -t nilesh-ips .`
2. Run the container with root privileges: `docker run --privileged nilesh-ips`
3. Access the Grafana dashboard to view real-time traffic analytics.
