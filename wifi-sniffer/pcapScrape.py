# imports

# formatting/debugging
import logging
from datetime import datetime
# pcap library
from scapy.all import *

# header vars
FILES = ['example-ft.pcapng', 'example-tptk-attack.pcapng', 'ipv4frags.pcap', 'nf9-juniper-vmx.pcapng.cap', 'smtp.pcap', 'teardrop.cap', 'nf9-error.pcapng.cap']

""" ********************************************** INITIATE LOGGING ********************************************** """
# initiate error logger
error_logger = logging.getLogger('error_logger')
error_logger.setLevel(logging.ERROR)
error_logger.propagate = False
file_handler = logging.FileHandler('error.log', mode='w')
# formatter
log_formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
file_handler.setFormatter(log_formatter) # configure file_handler
error_logger.addHandler(file_handler)

# initiate info logger

# print statements
info_logger = logging.getLogger('info_logger')
info_logger.setLevel(logging.INFO)
info_logger.propagate = False
# file handler
file_handler = logging.FileHandler('info.log',  mode='w') # reset every run
file_handler.setLevel(logging.INFO)

info_logger.addHandler(file_handler)

info_logger.info("************************************* PCAP FILE ANALYSIS *************************************\n")

""" ********************************************** PCAP FUNCTIONS ********************************************** """
# def extract_packet_details(packet):
#     if packet.haslayer(Dot11):
#         attributes = {}
#         for field in packet[Dot11].fields_desc:
#             field_name = field.name
#             field_value = packet[Dot11].fields.get(field_name, None)
#             attributes[field_name] = field_value 
    
#     info_logger.info('************************************* PACKET DETAIL *************************************\n')
#     for att, value in attributes.items():
#         info_logger.info(f'{att}: {value}')

def extract_packet_details(packet):
    layer_details = {}
    cur_layer = packet
    layer_count = 0 

    while cur_layer:
        layer_name = cur_layer.name
        layer_fields = {}

        if hasattr(cur_layer, 'fields_desc'):
            for field in cur_layer.fields_desc:
                field_name = field.name
                field_value = cur_layer.fields.get(field_name, None)
                layer_fields[field_name] = field_value
        layer_details[f'Layer_{layer_count}_{layer_name}'] = layer_fields
        cur_layer = cur_layer.payload
        layer_count += 1 

    info_logger.info('************************************* PACKET DETAIL *************************************\n')
    for layer, fields in layer_details.items():
        info_logger.info(f'{layer}:')
        for field_name, field_value in fields.items():
            info_logger.info(f' {field_name}: {field_value}')
        info_logger.info('\n')



# report_pcap
# threshold: modifier to adjust level of scrutiny (automatically set to 1)
def report_pcap(attackers, pcap_file, threshold=1):
    if any(data['count'] > threshold for data in attackers.values()):
        info_logger.info(f"\nPotential Attackers detected in {pcap_file}")
        for mac, data in attackers.items():
            if data["count"] > threshold:
                info_logger.info(f"  Source MAC: {mac} (Packets: {data['count']})")
                info_logger.info(f"  Blocked: {mac}\n")


# process_pcap
# takes file path and a flag
def process_pcap(pcap_file, block_traffic=False):
    packets = [] # declare empty list to stop error @ 111
    try:
        packets = rdpcap(pcap_file)
        info_logger.info(f'============================== {pcap_file.upper()} ==============================\n')
        info_logger.info(f"Successfully read {len(packets)} packets from {pcap_file}")
    except Exception as e:
        error_logger.error(f"Error reading {pcap_file}: {e}")
         

    attackers = {}

    def process_packet(packet, packet_number):
        nonlocal block_traffic  # Use the block_traffic flag from the outer function

        timestamp = float(packet.time)
        formatted_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        # packet extraction
        if Dot11 in packet: 
            extract_packet_details(packet)
            # get mac addresses
            src_mac = packet[Dot11].addr2 
            dst_mac = packet[Dot11].addr1

            if src_mac not in attackers: # unique mac not in attackers
                attackers[src_mac] = {"count": 1, "details": [(dst_mac)]}
            else: # else increment the # of times src_mac is seen
                attackers[src_mac]["count"] += 1
                attackers[src_mac]["details"].append(dst_mac) # append details

            if Dot11WEP in packet and packet[Dot11WEP].key_info & 64:
                reason = "Potential KRACK attack"
                info_logger.info(f"\nPacket {packet_number} flagged as potential attacker - Reason: {reason}")
                if block_traffic:
                    info_logger.info(f"Blocking traffic for this packet.")
                    info_logger.info(f"User dropped: {src_mac}")
                    return  # Exit the function, simulating blocking traffic
        else:
            src_ip = packet[IP].src if IP in packet else "N/A"
            dst_ip = packet[IP].dst if IP in packet else "N/A"
            src_port = packet.sport if packet.haslayer(IP) and packet.haslayer(TCP) else "N/A"
            dst_port = packet.dport if packet.haslayer(IP) and packet.haslayer(TCP) else "N/A"
            protocol = packet[IP].proto if IP in packet else "N/A"

            if not any(data["count"] > 0 for data in attackers.values()):
                # Print the entire packet details for non-Dot11 packets
                info_logger.info(f"\nPacket {packet_number} - Timestamp: {formatted_time} - Length: {len(packet)} bytes")
                info_logger.info(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
                info_logger.info(f"Source Port: {src_port}, Destination Port: {dst_port}, Protocol: {protocol}\n")
            elif block_traffic:
                reason = "Handshake failed"  # Simulated reason for blocking
                info_logger.info(f"\nPacket {packet_number} flagged as potential attacker - Reason: {reason}")
                info_logger.info(f"Blocking {src_ip}:{src_port} - Reason: {reason}")
                info_logger.info(f"User dropped: {src_ip}")
            else:
                # Print details of potential attacker packets
                if any(data["count"] > 0 for data in attackers.values()):
                    info_logger.info(f"\nPacket {packet_number} - Potential Attacker Details:")
                    info_logger.info(f"Source IP: {src_ip}, Destination IP: {dst_ip}")
                    info_logger.info(f"Source Port: {src_port}, Destination Port: {dst_port}, Protocol: {protocol}")
    
    for packet_number, packet in enumerate(packets, 1):
        process_packet(packet, packet_number)

    # Print blocking simulation if there are potential attackers and block_traffic is enabled
    if block_traffic and any(data["count"] > 0 for data in attackers.values()):
        info_logger.info(f"Blocking traffic for potential attackers.")
        return attackers

    return attackers


""" ********************************************** MAIN ********************************************** """
def main():
    for path in FILES:
        path = f'data/{path}'
        attackers = process_pcap(path, block_traffic=True)
        report_pcap(attackers, path)




if __name__ == '__main__':
    main()