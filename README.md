# Real-Time Network Intrusion Detection System (DoS Detection)

## Project Overview

This project implements a **Real-Time Network Intrusion Detection System (IDS)** designed to monitor network traffic and detect **Denial of Service (DoS) attacks** using packet analysis and behavioral detection techniques.

The system captures live network packets, extracts important traffic features, applies detection logic, and generates alerts when suspicious or malicious traffic patterns are detected.

A **real-time dashboard** is also included to visualize alerts, suspicious activity, and attack statistics.

---

# Key Features

• Real-time packet capture and monitoring  
• Detection of abnormal traffic patterns  
• DoS attack identification based on packet rate behavior  
• Risk classification:  
  - LOW → Normal traffic  
  - MEDIUM → Suspicious traffic  
  - HIGH → DoS attack  

• Attack source identification  
• Mitigation suggestion for detected attacks  
• Event logging system  
• Real-time monitoring dashboard  

---

# System Architecture

Network Traffic

↓

Packet Capture

↓

Feature Extraction

↓

Detection Engine

↓

Attack Identification

↓

Event Logging

↓

Real-Time Dashboard


---

# Project Structure

```
network_ids_project/

main_agent.py           # Main IDS engine
packet_capture.py       # Packet capturing module
feature_extractor.py    # Feature extraction logic
detection_engine.py     # Detection logic for attacks
traffic_generator.py    # DoS attack simulation tool
dashboard.py            # Real-time monitoring dashboard
ids_log.csv             # Event log file (generated during runtime)
```

---

# Dependencies / Required Libraries

Install the following Python libraries before running the project.

```bash
pip install scapy
pip install pandas
pip install streamlit
pip install numpy
```
Or install everything together:
```bash
pip install scapy pandas streamlit numpy
```

# How to Run the Project
**1. Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/network-ids-project.git
   cd network-ids-project
   ```

**NOTE :- Run Powershell as Administrator to run the below commands**

**2. Start the IDS Engine (Terminal 1)** 
   
   Run the main intrusion detection system:
   ```bash
   python main_agent.py
   ```

   This will begin capturing network packets and monitoring traffic.

**3. Start the Dashboard (Terminal 2)**

   Open another terminal and run:
   ```bash
   streamlit run dashboard.py
   ```

**4. Simulate a DoS Attack (Testing) - (Terminal 3)**

  Run the attack simulation tool in a separate terminal:
    
    python traffic_generator.py 
  This will generate high network traffic to test the IDS detection system.
