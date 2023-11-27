# imports
# formatting/debugging
import logging
from datetime import datetime
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

# info_logger.info("************************************* PCAP FILE ANALYSIS *************************************\n")
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

def process_pcap(pcap_file):
    packets = []
    try:
        packets = rdpcap(pcap_file)
        info_logger.info(f'============================== {pcap_file.upper()} ==============================')
        info_logger.info(f"Successfully read {len(packets)} packets from {pcap_file}")
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
    
    return pcap_info

def audit_probe_requests(pcap_info):
    count = 0
    last_seq_no = None
    

def analyze_packets(pcap_info):
    for packet in pcap_info:
        for key, value in packet.items():
            if value:
                info_logger.info(f'{key}: {value}')
        info_logger.info('\n')


def main():
    for path in FILES:
        path = f'data/{path}'
        pcap_info = process_pcap(path)
        analyze_packets(pcap_info)
        

if __name__ == '__main__':
    main()