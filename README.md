# ComputerSecurityMC-MitM

### SCRIPTS
Scripts used to detect WPA-1&2 nonce value duplication and a script to demonstrate Krack attacks

### WIG-NG
WIGS-NG

## Installation 
pip install wig-ng

## Supported Protocols & Standards

 - WiFi Protected Setup (WPS)
 - WiFi-Direct (P2P)
 - Cisco Client Extension (CCX)
 - Apple Wireless Direct Link (AWDL)
 - HP Printers Proprietary Information Element

## Usage

<pre>
usage: wig-ng.py [-h] [-v] [-c count] [-a]  
                 (-i network interface | -r pcap file | -R pcap directory)  
  
optional arguments:  
  -h, --help            show this help message and exit  
  -v, --verbose         Output verbosity (incremental).  
  -c count, --concurrent count  
                        Number of PCAP capture files to process  
                        simultaneously.  
  -a, --active          Some modules can perform frame injection, this is  
                        define by setting the active mode.  
  -i network interface, --interface network interface  
                        IEEE 802.11 network interface on monitor mode.  
  -r pcap file          PCAP capture file with IEEE 802.11 network traffic.  
  -R pcap directory     Directory with PCAP capture files.  
</pre>

## Usage Examples

**$** sudo iwconfig \<iface\> mode monitor  
**$** sudo ifconfig \<iface\> up  
**$** cd wig-ng  
**$** sudo python wig-ng.py -i \<iface\>