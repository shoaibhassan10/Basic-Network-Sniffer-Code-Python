
# Network Sniffer in Python

## Project Description
This project involves building a basic network sniffer using Python, which captures and analyzes network traffic. The sniffer captures packets on the network, allowing us to examine their structure and contents. This project provides a deeper understanding of how data flows across networks.

## Network Sniffer Code

```python
# Import the necessary libraries
from scapy.all import sniff

# Packet handler function to print details of captured packets
def packet_handler(packet):
    # Display basic details of each packet
    print(f"Packet: {packet.summary()}")
    
    # Show packet content in detail (uncomment if you want more details)
    # print(packet.show())

# Sniff the network and call the packet_handler function for each captured packet
print("Starting network sniffer...")
sniff(prn=packet_handler, store=0)  # prn is the callback function, store=0 means no storing of packets
```

## Explanation of Code
- **sniff() Function**: Captures packets from the network interface. By default, it captures from all interfaces.
  - `prn`: Callback function (`packet_handler`) to process each captured packet.
  - `store=0`: Prevents storing packets in memory.
  
- **packet_handler(packet) Function**: Processes each captured packet. Displays basic details using `packet.summary()`. You can uncomment `packet.show()` to see more detailed packet content.

## Filtering Packets
You can filter packets to capture only specific types, e.g., TCP packets:

```python
# Capture only TCP packets
sniff(filter="tcp", prn=packet_handler, store=0)
```

## Running the Sniffer
- **Run with Administrative Privileges**: Sniffing network traffic typically requires administrative or root privileges. Make sure to run the Python script as an administrator or with `sudo` on Linux/Mac.

```bash
sudo python3 network_sniffer.py
```

## Enhancements
- **Saving Captured Packets**: You can save the captured packets to a `.pcap` file for later analysis with tools like Wireshark:

```python
packets = sniff(count=10)  # Capture 10 packets
wrpcap('captured_packets.pcap', packets)  # Save to file
```

- **Packet Layer Analysis**: For more detailed analysis, access individual packet layers:

```python
def packet_handler(packet):
    if packet.haslayer('IP'):
        print(f"Source IP: {packet['IP'].src}")
        print(f"Destination IP: {packet['IP'].dst}")
        print(f"Protocol: {packet['IP'].proto}")
```

## Conclusion
This basic network sniffer captures and analyzes network traffic in real-time. It is a way to understand the structure of network packets and how data is transmitted over the network.
