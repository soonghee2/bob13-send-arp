# bob13-send-arp

This project is a learning exercise focused on understanding and implementing the Address Resolution Protocol (ARP) by sending custom ARP packets. It's designed to provide insights into how ARP works at a low level, including packet structure, network communication, and forging/sending raw network frames.

## Functionality:
This code likely demonstrates:
- **ARP Packet Construction:** How to manually build an ARP request or reply packet, including setting fields like hardware type, protocol type, hardware address length, protocol address length, opcode, sender hardware address, sender IP address, target hardware address, and target IP address.
- **Raw Socket Programming:** Utilizing raw sockets to send custom-crafted network packets directly over a network interface, bypassing higher-level protocol stacks.
- **Network Interface Interaction:** Identifying and interacting with local network interfaces to send packets.
- **Understanding ARP:** Deepening comprehension of ARP's role in mapping IP addresses to MAC addresses within a local network segment.

This project is valuable for anyone studying network protocols, low-level network programming, or network security, as it provides a practical example of fundamental network operations.
