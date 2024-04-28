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
import numpy as np
from time import time
from joblib import load

NETWORK_INTERFACE = ''
if system() == 'Linux':
    NETWORK_INTERFACE = 'ens33'
elif system() == 'Windows':
    NETWORK_INTERFACE = 'Realtek Gaming GbE Family Controller'

class PacketAnalysis:
    def __init__(self):
        self.columns = [
           'src_ip','dst_ip', 'dport', 'sport','time' ,'protocol', 'flags', 'time bw prev packet','spkts','dpkts' 
           ,'pkt_len', 'avgpkt','medpkt','stdpkt','avgBytes','medBytes','stdBytes','avgPktSz','medPktSz','stdPktSz', 'label'
        ]
        self.testing_cols = [
            'dport', 'sport','time' ,'protocol', 'time bw prev packet','spkts','dpkts' 
           ,'pkt_len', 'avgpkt','medpkt','stdpkt','avgBytes','medBytes','stdBytes','avgPktSz','medPktSz','stdPktSz', 'label'
        ]
        # 11-19 new data
        self.packet_info = []
        self.prev_packet_time = 0
        self.label = ''
        self.file_name = ''
        self.sessions = [] # List of dictionaries to hold packets
        self.local_pc_ip = get_if_addr(NETWORK_INTERFACE)
        self.tcp_pkt_count = 0
        self.udp_pkt_count = 0
        self.final_df = pd.DataFrame()
        self.start_time = time()
        self.model_loader = load('model_training/ssh_rf.pkl')
        signal.signal(signal.SIGINT, self._save_data_csv)

    def _save_data_csv(self, sig, frame):
        # Safe exit
        print('CTRL+C was used.')
        sys.exit(0)
    
    def _packet_analysis(self, packet):
        if IP in packet:
            if TCP in packet:
                self.tcp_pkt_count += 1
                current_packet_time = packet[TCP].time
                current_packet_info = {}
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
                current_packet_info[self.columns[11]] = self.tcp_pkt_count
                current_packet_info[self.columns[12]] = self.tcp_pkt_count
                current_packet_info[self.columns[13]] = self.tcp_pkt_count
                current_packet_info[self.columns[14]] = sys.getsizeof(packet[TCP].payload)
                current_packet_info[self.columns[15]] = sys.getsizeof(packet[TCP].payload)
                current_packet_info[self.columns[16]] = sys.getsizeof(packet[TCP].payload)
                current_packet_info[self.columns[17]] = sys.getsizeof(packet[TCP]) / self.tcp_pkt_count
                current_packet_info[self.columns[18]] = sys.getsizeof(packet[TCP]) / self.tcp_pkt_count
                current_packet_info[self.columns[19]] = sys.getsizeof(packet[TCP]) / self.tcp_pkt_count 
                self.packet_info.append(current_packet_info)
                if time() - self.start_time >= 30:
                    # After every 30 seconds create an aggregated dataframe
                    print('30 seconds passed')
                    self.start_time = time()
                    temp_df = pd.DataFrame(self.packet_info).drop(['src_ip', 'dst_ip', 'flags'], axis=1)
                    print(temp_df.head())
                    # temp_df = temp_df.agg({
                    #     self.columns[11]:'mean',
                    #     self.columns[12]:'median',
                    #     self.columns[13]: 'std',
                    #     self.columns[14]:'mean',
                    #     self.columns[15]:'median',
                    #     self.columns[16]: 'std',
                    #     self.columns[17]:'mean',
                    #     self.columns[18]:'median',
                    #     self.columns[19]: 'std',
                    # })
                    temp_df[self.columns[11]] = temp_df[self.columns[11]].mean()
                    temp_df[self.columns[12]] = temp_df[self.columns[12]].median()
                    temp_df[self.columns[13]] = temp_df[self.columns[13]].std()
                    temp_df[self.columns[14]] = temp_df[self.columns[11]].mean()
                    temp_df[self.columns[15]] = temp_df[self.columns[12]].median()
                    temp_df[self.columns[16]] = temp_df[self.columns[13]].std()
                    temp_df[self.columns[17]] = temp_df[self.columns[11]].mean()
                    temp_df[self.columns[18]] = temp_df[self.columns[12]].median()
                    temp_df[self.columns[19]] = temp_df[self.columns[13]].std()
                    self.final_df = pd.concat([self.final_df, temp_df])
                    prediction = self.model_loader.predict(temp_df)
                    print(prediction)

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
                current_packet_info[self.columns[11]] = self.tcp_pkt_count
                current_packet_info[self.columns[12]] = self.tcp_pkt_count
                current_packet_info[self.columns[13]] = self.tcp_pkt_count
                current_packet_info[self.columns[14]] = sys.getsizeof(packet[UDP].payload)
                current_packet_info[self.columns[15]] = sys.getsizeof(packet[UDP].payload)
                current_packet_info[self.columns[16]] = sys.getsizeof(packet[UDP].payload)
                current_packet_info[self.columns[17]] = sys.getsizeof(packet[UDP]) / self.tcp_pkt_count
                current_packet_info[self.columns[18]] = sys.getsizeof(packet[UDP]) / self.tcp_pkt_count
                current_packet_info[self.columns[19]] = sys.getsizeof(packet[UDP]) /self.tcp_pkt_count
                self.packet_info.append(current_packet_info)
                if time() - self.start_time >= 30:
                    # After every 30 seconds create an aggregated dataframe
                    print('30 seconds passed')
                    self.start_time = time()
                    temp_df = pd.DataFrame(self.packet_info).drop(['src_ip', 'dst_ip', 'flags'], axis=1)
                    # temp_df = temp_df.agg({
                    #     self.columns[11]:'mean',
                    #     self.columns[12]:'median',
                    #     self.columns[13]: 'std',
                    #     self.columns[14]:'mean',
                    #     self.columns[15]:'median',
                    #     self.columns[16]: 'std',
                    #     self.columns[17]:'mean',
                    #     self.columns[18]:'median',
                    #     self.columns[19]: 'std',
                    # })
                    temp_df[self.columns[11]] = temp_df[self.columns[11]].mean()
                    temp_df[self.columns[12]] = temp_df[self.columns[12]].median()
                    temp_df[self.columns[13]] = temp_df[self.columns[13]].std()
                    temp_df[self.columns[14]] = temp_df[self.columns[11]].mean()
                    temp_df[self.columns[15]] = temp_df[self.columns[12]].median()
                    temp_df[self.columns[16]] = temp_df[self.columns[13]].std()
                    temp_df[self.columns[17]] = temp_df[self.columns[11]].mean()
                    temp_df[self.columns[18]] = temp_df[self.columns[12]].median()
                    temp_df[self.columns[19]] = temp_df[self.columns[13]].std()
                    prediction = self.model_loader.predict(temp_df)
                    print('FROM UDP')
                    print(prediction)
                    
            
            elif ICMP in packet:
                print('ICMP PACKET RECEIVED!')

    def start_sniffer(self):
        print('sniffing started')
        sniff(iface=NETWORK_INTERFACE, 
                       prn=self._packet_analysis)


sniffer = PacketAnalysis()
sniffer.start_sniffer()
