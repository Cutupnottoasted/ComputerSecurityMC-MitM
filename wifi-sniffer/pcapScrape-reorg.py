import logging
from scapy.all import *
from scapy.layers.dot11 import Dot11

# Constants
FILES = ['example-tptk-attack.pcapng', 'example-ft.pcapng', 'ipv4frags.pcap', 'nf9-juniper-vmx.pcapng.cap', 'smtp.pcap', 'teardrop.cap', 'nf9-error.pcapng.cap', 'example-tptk-success.pcap']
WINDOW = 1.0
THRESHOLD = 10

# Logger setup
def setup_loggers():
    loggers = {}

    def setup_logger(name, level, filename):
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False
        file_handler = logging.FileHandler(filename, mode='w')
        file_handler.setLevel(level)
        log_formatter = logging.Formatter('%(asctime)s %(levelname)s:%(message)s')
        file_handler.setFormatter(log_formatter)
        logger.addHandler(file_handler)
        return logger

    loggers['error_logger'] = setup_logger('error_logger', logging.ERROR, 'error.log')
    loggers['suspicious_logger'] = setup_logger('suspicious_logger', logging.INFO, 'suspicious_packets.log')
    loggers['info_logger'] = setup_logger('info_logger', logging.INFO, 'info.log')
    loggers['security_logger'] = setup_logger('security_logger', logging.WARNING, 'security.log')

    return loggers

# Extract nonce from raw payload
def extract_nonce(raw_payload):
    start_offset = 13
    length = 32
    nonce = raw_payload[start_offset:start_offset + length]
    return nonce.hex()

# Identify subtype based on a given number
def identify_subtype(n):
    subtype_mapping = {
        0: 'Association Request',
        1: 'Association Response',
        4: 'Probe Request',
        5: 'Probe Response',
        8: 'Beacon',  # Handshake/broadcast
        11: 'Authentication',
        12: 'Deauthentication',
        13: 'Action',  # Receipt acknowledgement
    }
    return subtype_mapping.get(n, 'Unknown')

# Audit probe requests and check for suspicious behavior
def audit_probe_requests(attack):
    flag = False
    packets_per_sec = attack[-1][1] / len(attack)
    audit = f'Total Requests: {len(attack)} Total Time: {attack[-1][1]} Packets/Sec: {packets_per_sec}'
    if packets_per_sec < 1.0:
        flag = True
    return audit, flag

# Analyze packets and log information
def analyze_packets(pcap_info, logger):
    for packet in pcap_info:
        for key, value in packet.items():
            if value:
                logger.info(f'{key}: {value}')
        logger.info('\n')

# Process pcap file and create a dictionary of frame info
def process_pcap(pcap_file, logger):
    packets = []
    try:
        packets = rdpcap(pcap_file)
        logger.info(f'============================== {pcap_file.upper()} ==============================')
        logger.warning(f'============================== {pcap_file.upper()} ==============================\n')
        logger.info(f"Successfully read {len(packets)} packets from {pcap_file}\n")
    except Exception as e:
        logger.error(f"Error reading {pcap_file}: {e}")

    pcap_info = []

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

    return pcap_info

# Identify potential probe request attacks
def pull_probe_requests(pcap_info, window=WINDOW, threshold=THRESHOLD):
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

# Audit EAPOL requests and check for duplicate nonces
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

# Identify potential EAPOL attacks
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

# Main function to process pcap file, analyze packets, and log information
def main(pcap_file):
    pcap_file_path = f'data/{pcap_file}'
    loggers = setup_loggers()
    pcap_info = process_pcap(pcap_file_path, loggers['info_logger'])
    analyze_packets(pcap_info, loggers['info_logger'])

    # Process probe requests and log information
    potential_attacks = pull_probe_requests(pcap_info)
    for attack in potential_attacks:
        audit, flag = audit_probe_requests(attack)
        loggers['security_logger'].warning(f'{audit} -- Block Traffic: {flag}')
        packet_numbers = [num for num, _ in attack]
        loggers['security_logger'].warning(f'Suspicious Packets in {pcap_file_path}: {packet_numbers}\n')

        # Log details of suspicious packets to the new log file
        for num, _ in attack:
            loggers['suspicious_logger'].info(f'Packet Details for Suspicious Packet {num} in {pcap_file_path}:\n')
            for packet in pcap_info:
                if packet['No.'] == num:
                    for key, value in packet.items():
                        loggers['suspicious_logger'].info(f'{key}: {value}')
                    loggers['suspicious_logger'].info('\n')

    # Process EAPOL requests and log information
    potential_attacks = pull_eapol(pcap_info)
    for attack in potential_attacks:
        audit, flag = audit_eapol(attack)
        if audit:
            loggers['security_logger'].warning(f'{audit} -- Block Traffic: {flag} File: {pcap_file_path}\n')

    # Log separation lines in info and security log files
    loggers['info_logger'].info(f'============================== {pcap_file_path.upper()} ==============================\n')
    loggers['security_logger'].warning(f'============================== {pcap_file_path.upper()} ==============================\n')

if __name__ == "__main__":
    # Run the main function for each pcap file
    for pcap_file in FILES:
        main(pcap_file)
