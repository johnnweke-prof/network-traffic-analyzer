# Network Traffic Analyzer with Security Alerts

## TO RUN LOCALLY: 
- ** Ensure you have the Following installed:
- `python`
- `libpcap`
- `tcpdump` 
- `scapy` (python module)
- `tkinter` (python gui)

### What it should look Like:

##[IMAGE]

## Introduction

- **University:** Towson University  
- **Class:** COSC 519 - Operating Systems  
- **Student:** John Nweke  
- **Instructor:** Dr. Nicholas Phillips  
- **Project Brief Title:** Network Traffic Analyzer with Security Alerts  
- **Date:** September 17, 2024  

## OS Project Overview

This project focuses on creating a **network traffic analyzer** that monitors and captures data flowing through a network in real-time. It will analyze the captured data for unusual or unauthorized activities, such as port scans or DDoS attacks, and send out alerts when suspicious behavior is detected. Using packet-capturing tools, the project aims to provide insights into network traffic, identify potential security threats, and log or report them. The analyzer will offer users an intuitive way to monitor network activity and respond to security issues as they arise.

## Objectives

- **Capture** network packets in real-time.  
- **Analyze** packet headers to detect suspicious patterns (e.g., high traffic from a single IP, unusual port activity).  
- **Generate** security alerts based on predefined rules for common attacks.  
- **Implement** basic logging and reporting mechanisms for flagged traffic.  

## Materials and Resources

### Software

- **tcpdump** for packet capture (also using Wireshark).  
- **Python** (or **C**) for developing the analyzer and alert system.  
- **Linux** (preferred) or **Mac** OS for system-level packet capture.  

### Libraries/Tools

- **Scapy** (Python library) for packet manipulation and analysis.  
- **pcap** or **libpcap** for low-level packet capture.  
- **Syslog** for logging alerts and system events.  

### Documentation & Tutorials

- Official **Wireshark** and **tcpdump** documentation.  
- Linux **man pages** for networking commands and packet capture utilities.  
- Tutorials on using **Scapy** and **libpcap** for traffic analysis.  

## Expected Deliverables

- A functioning **network traffic analyzer** capable of monitoring and analyzing traffic.  
- **Security alerts** triggered by abnormal or suspicious network activity.  
- A **log file system** for recording flagged traffic.  

## Relevant Concept Areas

- **Operating Systems:** Utilize OS networking interfaces for packet capture and resource monitoring.  
- **Cybersecurity:** Implement basic intrusion detection techniques and security alerts.  
- **Networking:** Work with protocols such as **TCP/IP**, **DNS**, and **HTTP** to understand traffic behavior and detect anomalies.  

## Unusual Network Activities Indicating Cyber Incidents or Attacks

These activities below, including potential zero-day attacks, will be addressed by the program:

- **Unusual Spike in Traffic:** Sudden increase in inbound or outbound traffic without a legitimate cause.  
- **Unusual Port Scanning Activity:** Multiple probes on different ports from the same source IP.  
- **Unexpected Network Connections:** Outbound connections to unfamiliar or suspicious IP addresses.  
- **Frequent ICMP Traffic:** Excessive ping requests or echo replies (often used in DDoS or reconnaissance).  

## Project Description

The program is a hybrid version of **Wireshark** and **Snort**—built from scratch to offer custom network traffic analysis and security alerting.
