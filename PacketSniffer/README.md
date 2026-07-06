# CodeAlpha Cyber Security Internship - Task 1: Network Packet Sniffer

A Python-based network analysis tool developed using the Scapy framework to intercept, parse, and analyze live network traffic. This utility demonstrates core networking concepts, protocol encapsulation, and packet structure dissection.

---

## 🚀 Features
* **Live Packet Capture:** Hooks directly into the system's network stack to intercept passing traffic.
* **Protocol Dissection:** Automatically detects and categorizes Network Layer (`IP`) headers and Transport Layer (`TCP`, `UDP`, `ICMP`) data wrappers.
* **Payload Isolation:** Dissects the `Raw` application layer to expose and view data payloads traveling across the wires.
* **Memory Optimization:** Utilizes a real-time stream execution model (`store=0`) to process packets instantly without leaking system RAM.

---

## 🛠️ Prerequisites & Architecture
This script relies on Python 3 and the **Scapy** interactive packet-manipulation library.

### 1. Install Dependencies
Run the installation command in your terminal:
```bash
pip install scapyGIT