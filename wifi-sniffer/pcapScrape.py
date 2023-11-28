# imports
# formatting/debugging
import logging
from decimal import Decimal

# pcap library
from scapy.all import *
from scapy.layers.dot11 import Dot11

# 'example-ft.pcapng', 'ipv4frags.pcap', 'nf9-juniper-vmx.pcapng.cap', 'smtp.pcap', 'teardrop.cap', 'nf9-error.pcapng.cap', 'example-tptk-success.pcap'
file_handlers = []
# initiate error logger
error_logger = logging.getLogger('error_logger')
error_logger.setLevel(logging.ERROR)
error_logger.propagate = False
file_handler = logging.FileHandler('error.log', mode='w')
file_handlers.append(file_handler)
# formatter
log_formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
file_handler.setFormatter(log_formatter) # configure file_handler
error_logger.addHandler(file_handler)

# Create a new logger for suspicious packets
suspicious_logger = logging.getLogger('suspicious_logger')
suspicious_logger.setLevel(logging.INFO)
suspicious_logger.propagate = False
file_handler = logging.FileHandler('suspicious_packets.log', mode='w')
file_handlers.append(file_handler)
file_handler.setLevel(logging.INFO)
suspicious_logger.addHandler(file_handler)



# initiate info logger

# print statements
info_logger = logging.getLogger('info_logger')
info_logger.setLevel(logging.INFO)
info_logger.propagate = False
# file handler
file_handler = logging.FileHandler('info.log',  mode='w') # reset every run
file_handlers.append(file_handler)
file_handler.setLevel(logging.INFO)
info_logger.addHandler(file_handler)

security_logger = logging.getLogger('security_logger')
security_logger.setLevel(logging.WARNING)
security_logger.propagate = False
file_handler = logging.FileHandler('security.log', mode='w')
file_handlers.append(file_handler)
file_handler.setLevel(logging.WARNING)
security_logger.addHandler(file_handler)

info_logger.info("************************************* PCAP FILE OUTPUT *************************************\n")
security_logger.warning("************************************* PCAP FILE WARNINGS *************************************\n")
# formatted_time = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]


def extract_nonce(raw_payload):
    start_offset = 13
    length = 32
    nonce = raw_payload[start_offset:start_offset + length]
    return nonce.hex()

def identify_subtype(n):
    if n == 0:
        return 'Association Request'
    if n == 1:
        return 'Association Response'
    if n == 4:
        return 'Probe Request'
    if n == 5:
        return 'Probe Response'
    if n == 8: # Handshake/broadcast
        return 'Beacon'
    if n == 11:
        return 'Authentication'
    if n == 12:
        return 'Deauthentication'
    if n == 13: # receipt acknowledgement
        return 'Action'

def audit_probe_requests(attack):
    flag = False
    packets_per_sec = attack[-1][1] / len(attack) 
    audit = f'Total Requests: {len(attack)} Total Time: {attack[-1][1]} Packets/Sec: {packets_per_sec}'
    if packets_per_sec < 1.0:
        flag = True
    return audit, flag

def analyze_packets(pcap_info):
    for packet in pcap_info:
        for key, value in packet.items():
            if value:
                info_logger.info(f'{key}: {value}')
        info_logger.info('\n')

def process_pcap(pcap_file):
    packets = []
    try:
        packets = rdpcap(pcap_file)
        info_logger.info(f'============================== {pcap_file.upper()} ==============================')
        security_logger.warning(f'============================== {pcap_file.upper()} ==============================\n')
        info_logger.info(f"Successfully read {len(packets)} packets from {pcap_file}\n")
    except Exception as e:
        error_logger.error(f"Error reading {pcap_file}: {e}")

    pcap_info = []

    # create dictionary of frame info
    def process_packet(packet, packet_number):
        packet_info = {
            'No.': packet_number,
            'Time': packet.time,
            'Protocol': None,
            'Subtype': None,
            'Seq. No.': None,
            'Nonce': None
        }

        if packet.haslayer(Dot11):
            packet_info['Src'] = packet[Dot11].addr2
            packet_info['Dst'] = packet[Dot11].addr1
            packet_info['Protocol'] = '802.11'

            if hasattr(packet[Dot11], 'SC'):
                if packet[Dot11].SC:
                    packet_info['Seq. No.'] = packet[Dot11].SC >> 4

            if hasattr(packet[Dot11], 'subtype'):
                packet_info['Subtype'] = identify_subtype(packet[Dot11].subtype)

        if packet.haslayer('EAPOL'):
            packet_info['Protocol'] = 'EAPOL'
            packet_info['Nonce'] = extract_nonce(packet.load)
        
        pcap_info.append(packet_info)
    
    for packet_number, packet in enumerate(packets, 1):
        process_packet(packet, packet_number)
        
    # Set the effective level of the logger to INFO
    info_logger.setLevel(logging.INFO)
    analyze_packets(pcap_info)
            
    return pcap_info

def pull_probe_requests(pcap_info, window=1.0, threshold=10):
    probe_requests = [(packet['Time'], packet['No.']) for packet in pcap_info if packet['Protocol'] == '802.11' and packet.get('Subtype') == 'Probe Request']

    potential_attacks = []
    seen_packets = set()  # Store packet numbers already seen

    for i in range(len(probe_requests)):
        current_time, cur_packet_num = probe_requests[i]

        # Skip if seen
        if cur_packet_num in seen_packets:
            continue

        packets_in_window = [(cur_packet_num, 0)]

        for j in range(i + 1, len(probe_requests)):
            next_time, next_packet_num = probe_requests[j]
            elapsed_time = next_time - current_time
            if elapsed_time <= window:
                packets_in_window.append((next_packet_num, elapsed_time))
            else:
                break
        
        if len(packets_in_window) >= threshold:
            potential_attacks.append(packets_in_window)
            seen_packets.update(num for num, _ in packets_in_window)  # Add these packets to the set of counted packets

    return potential_attacks

def audit_eapol(attack):
    seen_nonce = {}
    flag = False
    audit = None
    dup_nonce = None

    for packet_num, nonce in attack:
        if nonce in seen_nonce:
            flag = True
            dup_nonce = nonce
            seen_nonce[nonce].append(packet_num)
        else:
            seen_nonce[nonce] = [packet_num]
    if flag:
        packet_numbers = seen_nonce[dup_nonce]
        audit = f'Duplicate nonce {dup_nonce} found in packets: {packet_numbers}'

    return audit, flag

def pull_eapol(pcap_info):
    eapol_requests = [(packet['No.'], packet['Nonce']) for packet in pcap_info if packet['Protocol'] == 'EAPOL' and packet.get('Subtype') == 'Beacon']

    potential_attacks = []
    seen_nonce = set()

    for packet_num, nonce in eapol_requests:
        if nonce in seen_nonce:
            continue
        seen_nonce.add(nonce)
        nonce_packets = [(num, n) for num, n in eapol_requests if n == nonce]
        potential_attacks.append(nonce_packets)

    return potential_attacks

     
def main(pcap):
    pcap_file = f'{pcap}'
    pcap_info = process_pcap(pcap_file)
    analyze_packets(pcap_info)

    # Create error, info, and security loggers as before
    # ...
    error_logger = logging.getLogger('error_logger')
    error_logger.setLevel(logging.ERROR)
    error_logger.propagate = False
    file_handler = logging.FileHandler('error.log', mode='w')
    file_handlers.append(file_handler)
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
    file_handlers.append(file_handler)
    file_handler.setLevel(logging.INFO)
    info_logger.addHandler(file_handler)
    
    security_logger = logging.getLogger('security_logger')
    security_logger.setLevel(logging.WARNING)
    security_logger.propagate = False
    file_handler = logging.FileHandler('security.log', mode='w')
    file_handlers.append(file_handler)
    file_handler.setLevel(logging.WARNING)
    security_logger.addHandler(file_handler)
    # Create a new logger for suspicious packets
    suspicious_logger = logging.getLogger('suspicious_logger')
    suspicious_logger.setLevel(logging.INFO)
    suspicious_logger.propagate = False
    file_handler = logging.FileHandler('suspicious_packets.log', mode='w')
    file_handlers.append(file_handler)
    file_handler.setLevel(logging.INFO)
    suspicious_logger.addHandler(file_handler)

    
    # Set the effective level of the logger to INFO
    info_logger.setLevel(logging.INFO)
    analyze_packets(pcap_info)
    
    # Process probe requests and log information
    potential_attacks = pull_probe_requests(pcap_info)
    for attack in potential_attacks:
        audit, flag = audit_probe_requests(attack)
        security_logger.warning(f'{audit} -- Block Traffic: {flag}')
        packet_numbers = [num for num, _ in attack]
        security_logger.warning(f'Suspicious Packets in {pcap_file}: {packet_numbers}\n')

        # Log details of suspicious packets to the new log file
        for num, _ in attack:
            suspicious_logger.info(f'Packet Details for Suspicious Packet {num} in {pcap_file}:\n')
            for packet in pcap_info:
                if packet['No.'] == num:
                    for key, value in packet.items():
                        suspicious_logger.info(f'{key}: {value}')
                    suspicious_logger.info('\n')

    # Process EAPOL requests and log information
    potential_attacks = pull_eapol(pcap_info)
    for attack in potential_attacks:
        audit, flag = audit_eapol(attack)
        if audit:
            security_logger.warning(f'{audit} -- Block Traffic: {flag} File: {pcap_file}\n')

    # Log separation lines in info and security log files
    info_logger.info(f'============================== {pcap_file.upper()} ==============================\n')
    security_logger.warning(f'============================== {pcap_file.upper()} ==============================\n')
    for handler in file_handlers:
        handler.close()
