# CSC521 - Communication Protocols

This repository is the laboratories and exercises of the course CSC521 at the National University of Kaohsiung.

## Focused Topic

### Lab1 - The basic development of pcap library

- The building system
- Listing network interfaces
- Sending packets
- Receiving packets

### Lab2 - Link layer protocols

- Address Resolution Protocol(ARP)
- ARP request
- ARP reply

### Lab3 - Network layer protocols

- Parital of Internet Protocol(IP)
- Partial of Internet Control Message Protocol(ICMP)
- ICMP echo request
- ICMP echo reply

### Lab4 - Transport layer protocols

- User Datagram Protocol(UDP)
- Partial of Transmission Contorl Protocl(TCP)
- Partial of Domain Name System(DNS)
- The complete DNS resolver

## Dependency

- libpcap

## TODO

- Refactor IP layer and UDP/TCP layer to reduce the coupling from upper-layers
- Enlarge the tosend_queue to avoid overwriting on sending packets
- Unify the naming
