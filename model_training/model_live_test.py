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
from joblib import load
from platform import system

NETWORK_INTERFACE = ''
if system() == 'Linux':
    NETWORK_INTERFACE = 'ens33'
elif system() == 'Windows':
    NETWORK_INTERFACE = 'Realtek Gaming GbE Family Controller'
    
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
        self.dt_model = load('model_training/ssh_rf.pkl')
        signal.signal(signal.SIGINT, self._save_data_csv)

    def _save_data_csv(self, sig, frame):
        # Once ctrl+c pressed, save data to csv
        print('Program Exited!')
        sys.exit(0)

    def _flags_to_encode(self, tcp_flags: str) -> int:
        if type(tcp_flags) != str:
            tcp_flags = str(tcp_flags)
        flag_mapping = {
            'F': '8',
            'S': '1',
            'R': '2',
            'P': '3',
            'A': '4',
            'U': '5',
            'E': '6',
            'C': '7',
            '0': '0',
            '9': '9'
        }
        list_of_flags = list()
        try:
            list_of_flags = list(tcp_flags)
        except:
            print(tcp_flags)
        encoded_flag = ''
        for flag in list_of_flags:
            encoded_flag += flag_mapping[flag]
        
        return int(encoded_flag)
    
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
                # current_packet_info[self.columns[8]] = packet[IP].ttl
                current_packet_info[self.columns[9]] = sys.getsizeof(packet[TCP].payload)
                # current_packet_info[self.columns[10]] = self.label
                self.packet_info.append(current_packet_info)
                # if packet[IP].src not in self.sessions:
                #     self.sessions.append({packet[IP].src: current_packet_info})
                # pprint(current_packet_info)

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
                # current_packet_info[self.columns[8]] = 0
                current_packet_info[self.columns[9]] = sys.getsizeof(packet[UDP].payload)
                # current_packet_info[self.columns[10]] = self.label
                self.packet_info.append(current_packet_info)

            try:
                # Predict the packet
                current_packet_info['flags'] = self._flags_to_encode(
                    tcp_flags=current_packet_info['flags']
                )
                df = pd.DataFrame([current_packet_info])
                prediction = self.dt_model.predict(df)
                if prediction != ['benign']:
                    print(prediction)
                    
            except UnboundLocalError:
                print('local var error')



    def start_sniffer(self):
        # self.label = input("label: ")
        # self.file_name = input("File name: ")
        # count = input('total packets to sniff: ')
        # filter = input('filter to apply: ')
        print('sniffing started')
        sniff(iface=NETWORK_INTERFACE, 
                       prn=self._packet_analysis)


sniffer = PacketAnalysis()
sniffer.start_sniffer()
