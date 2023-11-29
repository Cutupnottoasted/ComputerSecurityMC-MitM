import logging # formatting/debugging
from scapy.all import * # pcap library
from scapy.layers.dot11 import Dot11

file_handlers = []
# initiate error logger
error_logger = logging.getLogger('error_logger')
error_logger.setLevel(logging.ERROR)
error_logger.propagate = False
file_handler = logging.FileHandler('error.log', mode='w')
file_handlers.append(file_handler)
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
info_logger = logging.getLogger('info_logger')
info_logger.setLevel(logging.INFO)
info_logger.propagate = False
file_handler = logging.FileHandler('info.log',  mode='w') # reset every run
file_handlers.append(file_handler)
file_handler.setLevel(logging.INFO)
info_logger.addHandler(file_handler)

# initiate security logger
security_logger = logging.getLogger('security_logger')
security_logger.setLevel(logging.WARNING)
security_logger.propagate = False
file_handler = logging.FileHandler('security.log', mode='w')
file_handlers.append(file_handler)
file_handler.setLevel(logging.WARNING)
security_logger.addHandler(file_handler)

# Initial log statements
# info_logger.info("************************************* PCAP FILE OUTPUT *************************************\n")
# security_logger.warning("************************************* PCAP FILE WARNINGS *************************************\n")


# Extract nonce value from EAPOL payload 
def extract_nonce(raw_payload):
    start_offset = 13
    length = 32
    nonce = raw_payload[start_offset:start_offset + length]
    return nonce.hex() # convert to hexstring

# Function to identify subtype based on a given number
def identify_subtype(n):
    if n == 0:
        return 'Association Request'
    if n == 1:
        return 'Association Response'
    if n == 4:
        return 'Probe Request'
    if n == 5:
        return 'Probe Response'
    if n == 8: 
        return 'Beacon' # Handshake/broadcast
    if n == 11:
        return 'Authentication'
    if n == 12:
        return 'Deauthentication'
    if n == 13: 
        return 'Action' # receipt acknowledgement

# Function to audit probe requests and check for suspicious behavior
def analyze_packets(pcap_info):
    for packet in pcap_info:
        for key, value in packet.items():
            if value:
                info_logger.info(f'{key}: {value}')
        info_logger.info('\n')


# Function to process pcap file and create a dictionary of frame info
def process_pcap(pcap_file):
    packets = [] # avoid None error
    try:
        packets = rdpcap(pcap_file)
        info_logger.info(f"Successfully read {len(packets)} packets from {pcap_file}\n")
    except Exception as e:
        error_logger.error(f"Error reading {pcap_file}: {e}")

    pcap_info = [] 

    # Takes read packets from process_pcap and appends to pcap_info
    def process_packet(packet, packet_number):
        packet_info = {
            'No.': packet_number,
            'Time': packet.time,
            'Src': None,
            'Dst': None,
            'Protocol': None,
            'Subtype': None,
            'Seq. No.': None,
            'Nonce': None
        }

        if packet.haslayer(Dot11): # if packet contains Dot11 layer
            packet_info['Src'] = packet[Dot11].addr2
            packet_info['Dst'] = packet[Dot11].addr1
            packet_info['Protocol'] = '802.11'

            if hasattr(packet[Dot11], 'SC'): # if packet has sequence number
                if packet[Dot11].SC:
                    packet_info['Seq. No.'] = packet[Dot11].SC >> 4

            if hasattr(packet[Dot11], 'subtype'): # identify 802.11 subtype
                packet_info['Subtype'] = identify_subtype(packet[Dot11].subtype)

        if packet.haslayer('EAPOL'): # if 4-way-handshake
            packet_info['Protocol'] = 'EAPOL'
            packet_info['Nonce'] = extract_nonce(packet.load)
        
        pcap_info.append(packet_info) # append extracted fields into pcap_info list
    
    # process all read packets in pcap_file
    for packet_number, packet in enumerate(packets, 1):
        process_packet(packet, packet_number)
        
    # Set the effective level of the logger to INFO
    info_logger.setLevel(logging.INFO)
    analyze_packets(pcap_info)
            
    return pcap_info

# if the total packets_per_sec is > 1.0 then flag issue
def audit_probe_requests(attack):
    flag = False
    packets_per_sec = len(attack) / attack[-1][1] # Packets/sec = total target packets / total transmission time
    audit = f'Total Requests: {len(attack)} Total Time: {attack[-1][1]} Packets/Sec: {packets_per_sec}'
    if packets_per_sec > 1.0:
        flag = True
    return audit, flag

# Packets are extracted in bursts depending on the condition of packet capture
def pull_probe_requests(pcap_info, window=1.0, threshold=10):
    # insert packet field values Time and No. that are 802.11/Probe Request
    probe_requests = [(packet['Time'], packet['No.']) for packet in pcap_info 
                        if packet['Protocol'] == '802.11' and packet.get('Subtype') == 'Probe Request' or packet.get('Subtype') == 'Probe Response']

    potential_attacks = []
    seen_packets = set()  # store packet numbers already seen

    for i in range(len(probe_requests)):
        current_time, cur_packet_num = probe_requests[i]

        # skip if seen
        if cur_packet_num in seen_packets:
            continue

        packets_in_window = [(cur_packet_num, 0)] # initialize list with tuple

        # for all n-1 packets
        for j in range(i + 1, len(probe_requests)):
            next_time, next_packet_num = probe_requests[j] # get next packet arrival time/number
            elapsed_time = next_time - current_time
            if elapsed_time <= window: # if time between packets is < 1.0 secs
                packets_in_window.append((next_packet_num, elapsed_time)) # then append
            else:
                break
        
        if len(packets_in_window) >= threshold: # if window is full
            potential_attacks.append(packets_in_window)
            seen_packets.update(num for num, _ in packets_in_window)   # Add these packets to the set of counted packets

    return potential_attacks

# Searches for duplicate nonce values and reports if found
def audit_eapol(attack):
    seen_nonce = {}
    src_dst = [] # holds the src and dst with packet num as key

    dup_nonces = []
    flag = False
    audit = None

    # for tuple in packet_num and nonce in attacks
    for packet_num, nonce, src, dst in attack:
        if nonce in seen_nonce: # if nonce already seen
            flag = True
            dup_nonces.append(nonce)
            seen_nonce[nonce].append(packet_num)
            src_dst.append((src, dst))
        else:
            seen_nonce[nonce] = [packet_num]
            src_dst = [[packet_num, src, dst]]
    # if flag true then get packet_numbers and duplicate nonce
    if flag:
        for nonce in dup_nonces:
            packet_numbers = seen_nonce[nonce]
            if len(packet_numbers) == 2:
                flag = False
            audit = f'Duplicate nonce {nonce} found in packets: {packet_numbers}\n\nSource/Destination MAC addresses:'
            for num in packet_numbers:
                audit = audit + f'\n{num}: {src} -> {dst}'

    return audit, flag

# pulls all 4-way-handshake between client and host
def pull_eapol(pcap_info):
    # for values packet(No., Nonce) in pcap_info, if Protocol EAPOL and Subtype Beacon then insert to eapol_requests    
    eapol_requests = [(packet['No.'], packet['Nonce'], packet['Src'], packet['Dst']) for packet in pcap_info if packet['Protocol'] == 'EAPOL']

    potential_attacks = []
    seen_nonce = set()

    for _, nonce, src, dst in eapol_requests:
        if nonce in seen_nonce:
            continue
        seen_nonce.add(nonce)
        # Group packets by shared nonce values
        nonce_packets = [(num, n, src, dst) for num, n, _, _ in eapol_requests if n == nonce ]
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
        packet_numbers = [num for num, _ in attack] # grab all packets numbers in burst
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
            security_logger.warning(f'{audit}\nBlock Traffic: {flag}, File: {pcap_file}\n')

    for handler in file_handlers:
        handler.close()
