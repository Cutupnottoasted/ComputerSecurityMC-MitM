from datetime import datetime

from scapy.all import *


def process_pcap(pcap_file, block_traffic=False):
    try:
        packets = rdpcap(pcap_file)
        print(f"Successfully read {len(packets)} packets from {pcap_file}")
    except Exception as e:
        print(f"Error reading {pcap_file}: {e}")
        return None

    attackers = {}

    def process_packet(packet, packet_number):
        nonlocal block_traffic  # Use the block_traffic flag from the outer function

        timestamp = float(packet.time)
        formatted_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        if Dot11 in packet:
            src_mac = packet[Dot11].addr2
            dst_mac = packet[Dot11].addr1

            if src_mac not in attackers:
                attackers[src_mac] = {"count": 1, "details": [(dst_mac)]}
            else:
                attackers[src_mac]["count"] += 1
                attackers[src_mac]["details"].append(dst_mac)

            if Dot11WEP in packet and packet[Dot11WEP].key_info & 64:
                reason = "Potential KRACK attack"
                print(f"\nPacket {packet_number} flagged as potential attacker - Reason: {reason}")
                if block_traffic:
                    print(f"Blocking traffic for this packet.")
                    return  # Exit the function, simulating blocking traffic
        else:
            src_ip = packet[IP].src if IP in packet else "N/A"
            dst_ip = packet[IP].dst if IP in packet else "N/A"
            src_port = packet[IP].sport if IP in packet else "N/A"
            dst_port = packet[IP].dport if IP in packet else "N/A"
            protocol = packet[IP].proto if IP in packet else "N/A"

            # Print the entire packet details for non-Dot11 packets
            print(f"\nPacket {packet_number} - Timestamp: {formatted_time} - Length: {len(packet)} bytes")
            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
            print(f"Source Port: {src_port}, Destination Port: {dst_port}, Protocol: {protocol}")

            if block_traffic:
                reason = "Handshake failed"  # Simulated reason for blocking
                print(f"Packet {packet_number} flagged as potential attacker - Reason: {reason}")
                print(f"Blocking {src_ip}:{src_port} - Reason: {reason}")
                return  # Exit the function, simulating blocking traffic

    for packet_number, packet in enumerate(packets, 1):
        process_packet(packet, packet_number)

    # Print blocking simulation if there are potential attackers and block_traffic is enabled
    if block_traffic and any(data["count"] > 0 for data in attackers.values()):
        print(f"Blocking traffic for potential attackers.")
        return attackers

    return attackers

# Specify the names of your PCAP files
pcap_file1 = "example-tptk-attack.pcapng"
pcap_file2 = "nf9-juniper-vmx.pcapng.cap"

# Process the first pcap file
attackers1 = process_pcap(pcap_file1, block_traffic=True)

# Process the second pcap file
attackers2 = process_pcap(pcap_file2, block_traffic=True)

# Combine results or perform further analysis as needed
# For simplicity, this example just prints the results
threshold = 1

# Print or report potential attackers for the first file
if any(data["count"] > threshold for data in attackers1.values()):
    print(f"\nPotential Attackers detected in {pcap_file1}")
else:
    print(f"\nNo Potential Attackers detected in {pcap_file1}")

# Print or report potential attackers for the second file
if any(data["count"] > threshold for data in attackers2.values()):
    print(f"\nPotential Attackers detected in {pcap_file2}")
else:
    print(f"\nNo Potential Attackers detected in {pcap_file2}")