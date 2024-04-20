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
#import binascii
from pprint import pprint
import signal

class PacketAnalysis:
    def __init__(self):
        self.columns = [
            'dport', 'sport','protocol', 'tcp_flags', 'time bw prev packet' ,'pkt_len','ttl', 'payload size', 'label'
        ]
        self.packet_info = []
        self.prev_packet_time = 0
        signal.signal(signal.SIGINT, self._save_data_csv)

    def _save_data_csv(self, sig, frame):
        # Once ctrl+c pressed, save data to csv
        df = pd.DataFrame(self.packet_info)
        df.columns = self.columns
        df.to_csv('ddos_dataset.csv',index=False)
        print('CTRL+C was used.')
        sys.exit(0)

    # def _get_time_between(self, current_packet_time):

    
    def _packet_analysis(self, packet):
        if IP in packet:
            if TCP in packet:
                # print(ls(packet[TCP]))
                print(f"src ip: {packet[TCP].time}")
                # print(proto_field.i2s[packet.proto])
                # print(f"Payload size: {sys.getsizeof(bytes(packet[TCP].payload))}")
                # Save TCP flag data 
                current_packet_time = packet[TCP].time
                current_packet_info = {}
                current_packet_info[self.columns[0]] = packet[TCP].dport
                current_packet_info[self.columns[1]] = packet[TCP].dport
                current_packet_info[self.columns[2]] = 'tcp'
                current_packet_info[self.columns[3]] = str(packet[TCP].flags)
                current_packet_info[self.columns[4]] = current_packet_time - self.prev_packet_time
                self.prev_packet_time = current_packet_time
                current_packet_info[self.columns[5]] = len(packet[TCP].payload)
                current_packet_info[self.columns[6]] = packet[IP].ttl
                current_packet_info[self.columns[7]] = sys.getsizeof(packet[TCP].payload)
                current_packet_info[self.columns[8]] = 'dos'
                self.packet_info.append(current_packet_info)
                pprint(current_packet_info)

            elif ICMP in packet:
                # print(binascii.hexlify(bytes(packet[ICMP].payload)))
                print(f"ICMP timestamp: {packet[ICMP].time}")
            # elif UDP in packet:
            #     print(packet[UDP])


    def start_sniffer(self):
        print("start?")
        _ = input("")
        print('sniffing started')
        sniff(iface='Realtek Gaming GbE Family Controller', 
                       prn=self._packet_analysis, filter='src host 192.168.1.123')


sniffer = PacketAnalysis()
sniffer.start_sniffer()