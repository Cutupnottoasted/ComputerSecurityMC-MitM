example-ft.pcappng
- Beacon frames and probe responses
- network discovery/connection initiation
- Beacon frames are broadcasted by access point to announce network's presence and synchronize network members, while probe responses are sent by access points in resposne to probe requests

example-tptk-attack.pcapng
- includes beacon frames/probe responses
- has 4 way handshake 
    - is repeated with duplicate nonce value
- is deauthenticated at the end but is not signifier 

example-tptk-success.pcap
- includes beacon frames/ probe responses + 4way handshake
- a retransmission occurs after step 4
- both transmissions exclude step 2