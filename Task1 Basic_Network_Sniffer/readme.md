# Basic Network Sniffer

## Overview

This project was developed as part of the CodeAlpha Cyber Security Internship.

The Basic Network Sniffer is a Python-based tool that captures and analyzes network packets in real time using the Scapy library. It helps users understand network traffic by displaying packet information such as source and destination addresses, protocols, and packet statistics.

## Features

* Capture live network packets
* Select network interface for monitoring
* Detect TCP, UDP, and ICMP traffic
* Apply protocol filters
* Display packet statistics
* Save captured packets to PCAP files
* Analyze basic network traffic

## Technologies Used

* Python
* Scapy
* Npcap (Windows)

## Project Structure

```text
Task1_Basic_Network_Sniffer
│
├── sniffer.py
├── requirements.txt
├── sample_capture.pcap
└── README.md
```

## Installation

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run the program with administrator privileges:

```bash
python sniffer.py
```

Select the desired network interface and start monitoring network traffic.

## Learning Outcomes

Through this project, I learned:

* Network packet analysis
* Protocol identification
* Traffic monitoring techniques
* Packet capture using Scapy
* Basic cybersecurity monitoring concepts

## Author

Om Mehra

CodeAlpha Cyber Security Internship
