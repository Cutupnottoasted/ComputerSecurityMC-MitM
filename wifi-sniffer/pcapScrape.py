# imports
# formatting/debugging
import logging
from decimal import Decimal
# pcap library
from scapy.all import *
from scapy.layers.dot11 import Dot11

# 'example-ft.pcapng', 'ipv4frags.pcap', 'nf9-juniper-vmx.pcapng.cap', 'smtp.pcap', 'teardrop.cap', 'nf9-error.pcapng.cap', 'example-tptk-success.pcap'
FILES = ['example-tptk-attack.pcapng']

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

security_logger = logging.getLogger('security_logger')
security_logger.setLevel(logging.WARNING)
security_logger.propagate = False
file_handler = logging.FileHandler('security.log', mode='w')
file_handler.setLevel(logging.WARNING)
security_logger.addHandler(file_handler)

info_logger.info("************************************* PCAP FILE OUTPUT *************************************\n")
security_logger.warning("************************************* PCAP FILE WARNINGS *************************************\n")


# Extract nonce value from EAPOL payload 
def extract_nonce(raw_payload):
    start_offset = 13
    length = 32
    nonce = raw_payload[start_offset:start_offset + length]
    return nonce.hex() # convert to hexstring

# Find's subtype correct classification
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
        return 'Action' # Receipt acknowledgement
    
# Takes pcap packet bundles and outputs to info.log
def analyze_packets(pcap_info):
    for packet in pcap_info:
        for key, value in packet.items():
            if value:
                info_logger.info(f'{key}: {value}')
        info_logger.info('\n')

# process_pcap()
# input:
#   pcap_file: the path to target pcap_file
# output:
#   pcap_info: a list containing processed packet data
#   
# Reads pcap_file and then sends read packets into process_packet()
# Target fields are assigned to packet_info struct then appended into pcap_info
def process_pcap(pcap_file):
    packets = [] # avoid None error
    try:
        packets = rdpcap(pcap_file)
        info_logger.info(f'============================== {pcap_file.upper()} ==============================')
        security_logger.warning(f'============================== {pcap_file.upper()} ==============================\n')
        info_logger.info(f"Successfully read {len(packets)} packets from {pcap_file}\n")
    except Exception as e:
        error_logger.error(f"Error reading {pcap_file}: {e}")

    pcap_info = [] 

    # process_packet()
    # input:
    #   packet: indvidual packet
    #   packet_number: packet number in .pcap file
    # 
    # Takes read packets from process_pcap and extracts target
    # data and assignes it to packet_info structure. 
    # completed packet_info is appended to pcap_info list
    def process_packet(packet, packet_number):
        packet_info = {
            'No.': packet_number,
            'Time': packet.time,
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
    
    return pcap_info

# audit_probe_requests()
# input:
#   attacks: contains burst of probe requests
# output:
#   audit: string containing security message
#   flag: if true then block traffic
# if the total packets_per_sec is > 1.0 then flag issue
def audit_probe_requests(attacks):
    flag = False
    packets_per_sec = len(attacks) / attacks[-1][1] # Packets/sec = total target packets / total transmission time
    audit = f'Total Requests: {len(attacks)} Total Time: {attacks[-1][1]} Packets/Sec: {packets_per_sec}'
    if packets_per_sec > 1.0:
        flag = True
    return audit, flag

# pull_probe_requests()
# input: 
#   pcap_info: Contains all target fields extracted from process_packet()
#   window = 1.0: If packets/sec are > 1.0 seconds then flag
#   threshhold = 10: If number of packets_in_window > 10 then
#       update set() and append to potential attacks.
# output:
#   potential_attacks: list containing all extracted probe requests
#
# Packets are extracted in bursts depending on the condition of packet capture
def pull_probe_requests(pcap_info, window=1.0, threshold=10):

    # for values packet(Time, No.) in pcap_info, if packet's protocol is 802.11 and Subtype is Probe Request then insert into probe_requests
    probe_requests = [(packet['Time'], packet['No.']) for packet in pcap_info if packet['Protocol'] == '802.11' and packet.get('Subtype') == 'Probe Request']

    potential_attacks = [] 
    seen_packets = set()  # store packet numbers already seen

    for i in range(len(probe_requests)):
        current_time, cur_packet_num = probe_requests[i]

        # skip seen packets
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
            seen_packets.update(num for num, _ in packets_in_window)  # Add these packets to the set of counted packets

    return potential_attacks

# audit_eapol()
# input:
#   attacks: a tuple of n packets containing packet number and nonce value
# output:
#   audit: the results from packet analysis
#   flag: if true block_traffic
#
# Searches for duplicate nonce values and reports if found
def audit_eapol(attacks): 
    seen_nonce = {}
    flag = False 
    audit = None
    dup_nonce = None

    # for tuple packet_num and nonce in attacks
    for packet_num, nonce in attacks:
        if nonce in seen_nonce: # if nonce already seen
            flag = True
            dup_nonce = nonce
            seen_nonce[nonce].append(packet_num)
        else:
            seen_nonce[nonce] = [packet_num]
    # if flag true then get packet_numbers and duplicate nonce
    if flag: 
        packet_numbers = seen_nonce[dup_nonce]
        audit = f'Duplicate nonce {dup_nonce} found in packets: {packet_numbers}'

    return audit, flag

# pull_eapol()
# input:
#   pcap_info: contains all extracted fields from each packet
# output:
#   potential_attackers: contains all 4-way-handshakes packets that had duplicate nonce values
#
# pulls all 4-way-handshake between client and host
def pull_eapol(pcap_info):
    # for values packet(No., Nonce) in pcap_info, if Protocol EAPOL and Subtype Beacon then insert to eapol_requests
    eapol_requests = [(packet['No.'], packet['Nonce']) for packet in pcap_info if packet['Protocol'] == 'EAPOL' and packet.get('Subtype') == 'Beacon']

    potential_attacks = []
    seen_nonce = set()

    for packet_num, nonce in eapol_requests:
        if nonce in seen_nonce:
            continue
        seen_nonce.add(nonce)
        # for each tuple (No., Nonce) in eapol_requests if n == nonce then append to nonce_packets
        nonce_packets = [(num, n) for num, n in eapol_requests if n == nonce]
        potential_attacks.append(nonce_packets)

    return potential_attacks

     
def main():
    # for all pcap_files in the data directory
    for pcap_file in FILES:
        pcap_file = f'data/{pcap_file}'
        pcap_info = process_pcap(pcap_file) # open and structure pcap data
        analyze_packets(pcap_info) # analyze structure data

    potential_attacks = pull_probe_requests(pcap_info) # pull all probe requests
    for attack in potential_attacks: # audit probe requests by burst
        audit, flag = audit_probe_requests(attack) 
        security_logger.warning(f'{audit} -- Block Traffic: {flag}')
        packet_numbers = [num for num, _ in attack] # grab all packets numbers in burst
        security_logger.warning(f'Suspicious Packets in {pcap_file}: {packet_numbers}\n')

    potential_attacks = pull_eapol(pcap_info) # pull all 4-way-handshakes
    for attacks in potential_attacks: # audit each 4-way-handshake session
        audit, flag = audit_eapol(attacks)
        if audit:
            security_logger.warning(f'{audit} -- Block Traffic: {flag} File: {pcap_file}\n')

    info_logger.info(f'============================== {pcap_file.upper()} ==============================\n')
    security_logger.warning(f'============================== {pcap_file.upper()} ==============================\n')

if __name__ == '__main__':
    main()