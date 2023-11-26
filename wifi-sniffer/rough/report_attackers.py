    # init_info_logger()
    # Specify the names of your PCAP files
    pcap_file1 = "data/teardrop.cap"
    pcap_file2 = "data/example-tptk-attack.pcapng"

    # Process the first pcap file
    attackers1 = process_pcap(pcap_file1, block_traffic=True)

    # Process the second pcap file
    attackers2 = process_pcap(pcap_file2, block_traffic=True)
    
    # Combine results or perform further analysis as needed
    # For simplicity, this example just prints the results
    threshold = 1

    # Print or report potential attackers for the first file
    if any(data["count"] > threshold for data in attackers1.values()):
        info_logger.info(f"\nPotential Attackers detected in {pcap_file1}")
        for mac, data in attackers1.items():
            if data["count"] > threshold:
                info_logger.info(f"  Source MAC: {mac} (Packets: {data['count']})")
                info_logger.info(f"  Blocked: {mac}\n")

    # Print or report potential attackers for the second file
    if any(data["count"] > threshold for data in attackers2.values()):
        info_logger.info(f"\nPotential Attackers detected in {pcap_file2}")
        for mac, data in attackers2.items():
            if data["count"] > threshold:
                info_logger.info(f"  Source MAC: {mac} (Packets: {data['count']})")
                info_logger.info(f"  Blocked: {mac}\n")
