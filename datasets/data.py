"""
    This python will be used to create the data for our machine learning model.
    We will first try to create our data targeting 3 common attacks:
    1. DoS
    2. SSH-Bruteforce
    3. FTP-Bruteforce
"""

from scapy.all import *
import pandas as pd
import sys
from pprint import pprint
import signal

NETWORK_INTERFACE='ens33'

class PacketAnalysis:
    def __init__(self):
        self.columns = [
            'dport', 'sport','protocol', 'flags', 'time bw prev packet','spkts','dpkts' ,'pkt_len','ttl', 'payload size', 'label'
        ]
        self.packet_info = []
        self.prev_packet_time = 0
        self.label = ''
        self.file_name = ''
        self.sessions = [] # List of dictionaries to hold packets
        self.local_pc_ip = get_if_addr(NETWORK_INTERFACE)
        signal.signal(signal.SIGINT, self._save_data_csv)

    def _save_data_csv(self, sig, frame):
        # Once ctrl+c pressed, save data to csv
        df = pd.DataFrame(self.packet_info)
        df.columns = self.columns
        df.to_csv(self.file_name,index=False)
        print('CTRL+C was used.')
        sys.exit(0)
    
    def _packet_analysis(self, packet):
        if IP in packet:
            if TCP in packet:
                current_packet_time = packet[TCP].time
                current_packet_info = {}
                # current_packet_info['src_ip'] = packet[IP].src
                # current_packet_info['dst_ip'] = packet[IP].dst
                current_packet_info[self.columns[0]] = packet[TCP].dport
                current_packet_info[self.columns[1]] = packet[TCP].sport
                current_packet_info[self.columns[2]] = packet[IP].proto
                current_packet_info[self.columns[3]] = str(packet[TCP].flags)
                current_packet_info[self.columns[4]] = current_packet_time - self.prev_packet_time
                self.prev_packet_time = current_packet_time
                if packet[IP].src == self.local_pc_ip:
                    # Get the size of source to destination packets
                    current_packet_info[self.columns[5]] = len(bytes(packet[TCP]))
                    current_packet_info[self.columns[6]] = 0
                elif packet[IP].src != self.local_pc_ip:
                    # Get the size of dest to source packets
                    current_packet_info[self.columns[5]] = 0
                    current_packet_info[self.columns[6]] = len(bytes(packet[TCP]))
                current_packet_info[self.columns[7]] = len(packet[TCP].payload)
                current_packet_info[self.columns[8]] = packet[IP].ttl
                current_packet_info[self.columns[9]] = sys.getsizeof(packet[TCP].payload)
                current_packet_info[self.columns[10]] = self.label
                self.packet_info.append(current_packet_info)
                # if packet[IP].src not in self.sessions:
                #     self.sessions.append({packet[IP].src: current_packet_info})
                pprint(current_packet_info)

            elif UDP in packet:
                current_packet_time = packet[UDP].time
                current_packet_info = {}
                # current_packet_info['src_ip'] = packet[IP].src
                # current_packet_info['dst_ip'] = packet[IP].dst
                current_packet_info[self.columns[0]] = packet[UDP].sport
                current_packet_info[self.columns[1]] = packet[UDP].dport
                current_packet_info[self.columns[2]] = packet[IP].proto
                current_packet_info[self.columns[3]] = 0
                current_packet_info[self.columns[4]] = current_packet_time - self.prev_packet_time
                self.prev_packet_time = current_packet_time
                if packet[IP].src == self.local_pc_ip:
                    # Get the size of source to destination packets
                    current_packet_info[self.columns[5]] = len(bytes(packet[UDP]))
                    current_packet_info[self.columns[6]] = 0
                elif packet[IP].src != self.local_pc_ip:
                    # Get the size of dest to source packets
                    current_packet_info[self.columns[5]] = 0
                    current_packet_info[self.columns[6]] = len(bytes(packet[UDP]))
                current_packet_info[self.columns[7]] = len(packet[UDP].payload)
                current_packet_info[self.columns[8]] = 0
                current_packet_info[self.columns[9]] = sys.getsizeof(packet[UDP].payload)
                current_packet_info[self.columns[10]] = self.label
                self.packet_info.append(current_packet_info)

                """TODO: Update this code to capture ICMP info as well"""


    def start_sniffer(self):
        self.label = input("label: ")
        self.file_name = input("File name: ")
        count = input('total packets to sniff: ')
        filter = input('filter to apply: ')
        print('sniffing started')
        sniff(iface=NETWORK_INTERFACE, 
                       prn=self._packet_analysis, filter=filter, count=int(count))
        df = pd.DataFrame(self.packet_info)
        df.columns = self.columns
        df.to_csv(self.file_name + '.csv', index=False)


sniffer = PacketAnalysis()
sniffer.start_sniffer()
