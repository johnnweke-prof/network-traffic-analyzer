#!/usr/bin/env python3

# Declare Python Shebang to Run this as a bash script

#####################################################
# IMPORTS

import logging
from scapy.all import sniff
from collections import defaultdict
import tkinter as tk
from tkinter import scrolledtext
import threading  # For running sniffing in a separate thread

###################################################

# LOGGING SETUP

# Configure logging
logging.basicConfig(
    filename="alerts.log",
    level=logging.INFO,
    format='%(asctime)s %(message)s'
)

###################################################

# NETWORK TRAFFIC ANALYZER CODE

# Dictionaries to keep track of suspicious activity
packet_count = defaultdict(int)
port_count = defaultdict(set)


#####################################

# Function to handle each captured packet
def packet_callback(packet):
    try:
        ip_src = None  # Initialize ip_src to avoid undefined access
        # This is what made the code break when I ran it in class 
        # I did not initialize IP-SRC
        
        
        if packet.haslayer("IP"):
            ip_src = packet["IP"].src
            packet_count[ip_src] += 1

            # HIGH TRAFFIC
            if packet_count[ip_src] > 1000:
                alert_msg = f"ALERT: High traffic from IP {ip_src}"
                log_alert(alert_msg)

        # PORT SCAN
        if packet.haslayer("TCP") and ip_src:
            port_dst = packet["TCP"].dport
            port_count[ip_src].add(port_dst)

            if len(port_count[ip_src]) > 10:
                alert_msg = f"ALERT: Potential port scan from {ip_src}"
                log_alert(alert_msg)

    except Exception as e:
        error_msg = f"Error processing packet: {e}"
        log_alert(error_msg)  # Display error in the GUI
        
#################################################

# Function to log alerts to the GUI and file
def log_alert(message):
    alert_textbox.insert(tk.END, f"{message}\n")
    alert_textbox.see(tk.END)  # This will Auto-scroll to the latest alerts
    logging.info(message)

# Function to start sniffing packets in a new thread
def start_sniffing():
    sniff_thread = threading.Thread(target=sniff, kwargs={"prn": packet_callback, "store": False})
    sniff_thread.daemon = True  # Ensure the thread exits when the main program does
    sniff_thread.start()

# Function to stop the application
def stop_sniffing():
    root.quit()

#######################################

# GUI SECTION

# Set up the GUI
root = tk.Tk()
root.title("Network Traffic Analyzer")

# Adding a label
label = tk.Label(root, text="Security Alerts", font=("Helvetica", 20))
label.pack()

# Adding a scrolling text box for displaying alerts
alert_textbox = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=30, width=60)
alert_textbox.pack()

# Adding start and stop buttons
start_button = tk.Button(root, text="START", command=start_sniffing, width=10, height=3, bg="white", fg="black")
start_button.pack(pady=7)

stop_button = tk.Button(root, text="STOP", command=stop_sniffing, width=10, height=3, bg="black", fg="white")
stop_button.pack(pady=7)

# Running the GUI event loop
root.mainloop()


