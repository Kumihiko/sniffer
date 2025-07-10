Network Sniffer with Protocol Filtering and Detailed Packet Analysis
Overview
This Python application is a user-friendly network packet sniffer with a graphical interface (Tkinter) that allows you to capture, filter, and analyze network traffic in real-time.
It supports filtering by protocol, IP addresses, and ports, and displays detailed packet information, including special parsing for HTTP and DNS protocols.
Additionally, it provides live statistics showing the number of packets captured per protocol.

Features

  Capture live network traffic from your machine using Scapy.

  Filter packets by protocol (ICMP, TCP, UDP, and more), IP address substrings, and port substrings.
  
  Display captured packets in a table with source/destination IP, protocol, and ports.
  
  View detailed packet data in a dedicated window with full packet dump and human-readable HTTP and DNS details when available.
  
  Live protocol statistics updated every second.
  
  Easy start/stop sniffing controls in a clean and intuitive GUI.

Technologies

  Python 3

  Scapy — powerful packet capture and manipulation library.

  Tkinter — native Python GUI toolkit.

