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
from platform import system
from datetime import datetime

NETWORK_INTERFACE = ''
if system() == 'Linux':
    NETWORK_INTERFACE = 'ens33'
elif system() == 'Windows':
    NETWORK_INTERFACE = 'Realtek Gaming GbE Family Controller'

class PacketAnalysis:
    def __init__(self):
        self.columns = [
           'src_ip','dst_ip', 'dport', 'sport','time' ,'protocol', 'flags', 'time bw prev packet','spkts','dpkts' ,'pkt_len','ttl', 'payload size', 'label'
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
        df.to_csv(self.file_name + '.csv',index=False)
        print('CTRL+C was used.')
        sys.exit(0)
    
    def _packet_analysis(self, packet):
        if IP in packet:
            if TCP in packet:
                current_packet_time = packet[TCP].time
                current_packet_info = {}
                # current_packet_info['src_ip'] = packet[IP].src
                # current_packet_info['dst_ip'] = packet[IP].dst
                current_packet_info[self.columns[0]] = packet[IP].src
                current_packet_info[self.columns[1]] = packet[IP].dst
                current_packet_info[self.columns[2]] = packet[TCP].dport
                current_packet_info[self.columns[3]] = packet[TCP].sport
                current_packet_info[self.columns[4]] = packet[TCP].time
                current_packet_info[self.columns[5]] = packet[IP].proto
                current_packet_info[self.columns[6]] = str(packet[TCP].flags)
                current_packet_info[self.columns[7]] = current_packet_time - self.prev_packet_time
                self.prev_packet_time = current_packet_time
                if packet[IP].src == self.local_pc_ip:
                    # Get the size of source to destination packets
                    current_packet_info[self.columns[8]] = len(bytes(packet[TCP]))
                    current_packet_info[self.columns[9]] = 0
                elif packet[IP].src != self.local_pc_ip:
                    # Get the size of dest to source packets
                    current_packet_info[self.columns[8]] = 0
                    current_packet_info[self.columns[9]] = len(bytes(packet[TCP]))
                current_packet_info[self.columns[10]] = len(packet[TCP].payload)
                current_packet_info[self.columns[11]] = packet[IP].ttl
                current_packet_info[self.columns[12]] = sys.getsizeof(packet[TCP].payload)
                current_packet_info[self.columns[13]] = self.label
                # Perform aggregation here
                if len(self.packet_info) == 10:
                    grouped_data = pd.DataFrame(self.packet_info)
                    grouped_data['time'] = pd.to_datetime(grouped_data['time'], unit='s')
                    grouped_data = grouped_data.groupby(['src_ip', 'dst_ip','dport'])
                    aggregated_data = []
                    for group, data in grouped_data:
                        data = data.drop(['src_ip', 'dst_ip', 'sport', 'dport'], axis=1)
                        resampled_data = data.resample('5s', on='time').mean()
                        resampled_data = pd.concat([data[['src_ip', 'dst_ip', 'sport', 'dport']], resampled_data], axis=1)
                        aggregated_data.append(resampled_data)
                    aggregated_data = pd.concat(aggregated_data)
                    print(aggregated_data.head())
                    aggregated_data.to_csv('agg.csv', index=False)
                self.packet_info.append(current_packet_info)

            elif UDP in packet:
                current_packet_time = packet[UDP].time
                current_packet_info = {}
                current_packet_info[self.columns[0]] = packet[IP].src
                current_packet_info[self.columns[1]] = packet[IP].dst
                current_packet_info[self.columns[2]] = packet[UDP].sport
                current_packet_info[self.columns[3]] = packet[UDP].dport
                current_packet_info[self.columns[4]] = packet[UDP].time
                current_packet_info[self.columns[5]] = packet[IP].proto
                current_packet_info[self.columns[6]] = 0
                current_packet_info[self.columns[7]] = current_packet_time - self.prev_packet_time
                self.prev_packet_time = current_packet_time
                if packet[IP].src == self.local_pc_ip:
                    # Get the size of source to destination packets
                    current_packet_info[self.columns[8]] = len(bytes(packet[UDP]))
                    current_packet_info[self.columns[9]] = 0
                elif packet[IP].src != self.local_pc_ip:
                    # Get the size of dest to source packets
                    current_packet_info[self.columns[8]] = 0
                    current_packet_info[self.columns[9]] = len(bytes(packet[UDP]))
                current_packet_info[self.columns[10]] = len(packet[UDP].payload)
                current_packet_info[self.columns[11]] = 0
                current_packet_info[self.columns[12]] = sys.getsizeof(packet[UDP].payload)
                current_packet_info[self.columns[13]] = self.label
                self.packet_info.append(current_packet_info)
                pprint(current_packet_info)

                """TODO: Update this code to capture ICMP info as well"""
            
            elif ICMP in packet:
                print('ICMP PACKET RECEIVED!')

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
