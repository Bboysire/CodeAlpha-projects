import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
#install scapy using pip install scapy (windows) or pip3 install scapy (linux)

def process_packet(packet):
    """
    Callback function executed for every intercepted packet.
    Extracts and displays key network architecture data points.
    """
    #  Analyze Traffic Structure & Extract Key Information
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        
        # Map protocol numbers to human-readable string names
        protocol = "UNKNOWN"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = f"IP Protocol {proto_num}"
            
        print(f"\n[+] New Packet: {src_ip} -> {dst_ip} | Protocol: {protocol}")
        
        # Extract Packet Payload if it exists
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # Print a readable, safe representation of the raw payload bytes
            print(f"    Payload: {payload[:100]}") # Truncated to 100 characters for readability
        else:
            print("    Payload: None (Empty Header/Control Packet)")

def main():
    print("[*] Starting CodeAlpha Basic Network Sniffer...")
    print("[*] Intercepting network traffic... Press Ctrl+C to stop.")
    
    try:
        # Develop a Packet Capture Program
        # store=0 ensures packets are processed on the fly without consuming massive RAM
        sniff(prn=process_packet, store=0)
    except PermissionError:
        print("\n[!] Error: Root/Administrative privileges required to sniff packets.", file=sys.stderr)
        print("[!] Please run this script using 'sudo python3 sniffer.py' on Linux.", file=sys.stderr)
        sys.exit(1)
        #catches the permission error if the user does not have root/admin privileges and exits gracefully
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped successfully.")
        sys.exit(0)
        #catches the ctrl+c keyboard interrupt and exits gracefully

if __name__ == "__main__":
    main()