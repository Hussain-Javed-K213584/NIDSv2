from tkinter import *
import tkinter.scrolledtext as scrolledtext
from scapy.all import *
from joblib import load
import threading
import os
import pandas as pd
import configparser
import yara
import logging

sniffer_stop = False
textbox = None
sniffer_thread = None

class NIDS:
    def __init__(self):
          src_path = os.path.dirname(os.path.abspath(__file__))
          file_path = os.path.join(src_path,'../model_training/dt_classifier.pkl')
          rule_file_path = os.path.join(src_path,'rules.conf')
          yara_dir = os.path.join(src_path, 'yara-rules')
          # store all yara files inside a list
          self.yara_files = [f for f in os.listdir(yara_dir) if os.path.isfile(os.path.join(yara_dir,f))]
          self.dt_model = load(file_path)
          self.columns = [
           'dport', 'sport','protocol', 'flags', 'time bw prev packet','spkts','dpkts' ,'pkt_len','ttl', 'payload size'
          ]
          self.packet_info = []
          self.prev_packet_time = 0
          self.label = ''
          self.file_name = ''
          self.local_pc_ip = get_if_addr('Realtek Gaming GbE Family Controller')
          self.config_parser = configparser.ConfigParser()
          self.config_parser.read(rule_file_path)
          self.rule_dictionary = []
          logging.basicConfig(filename='alerts.log', filemode='a',format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')


    # TODO: Implementing yara rules for NIDS and match packet payloads against the yara rules
    def yara_rules_match(self,packet_payload):
        # print(self.yara_files)
        return

    # TODO: Implement NIDS rules. Use a config file for that.
    def rule_parser(self):
        """
            Parses a config file on allow and deny requests
        """
        ip_list = self.config_parser['RULE']['ip'].split(',')
        port_list = self.config_parser['RULE']['port'].split(',')
        proto_list = self.config_parser['RULE']['protocol'].split(',')
        state_list = self.config_parser['RULE']['state'].split(',')
        if not len(state_list) == len(ip_list) == len(port_list) == len(proto_list):
            print("Invalid rule")
            exit()
        # Converting the rule to a list of dictionaries
        
        for i in range(len(ip_list)):
            temp_dict = {
                'ip':ip_list[i],
                'port':port_list[i],
                'protocol':proto_list[i]
            }
            self.rule_dictionary.append(temp_dict)


    def _stop_sniffing(self,pkt):
        global sniffer_stop
        return sniffer_stop

    def _starter(self,start_button:Button,stop_button:Button):
        """
            Button command which disables the `start button`
            and enables the `stop button`. It also starts
            the live sniffing process by started another python process.
        """
        global sniffer_stop
        global sniffer_thread
        self.rule_parser()
        start_button.config(state=DISABLED)
        if (sniffer_thread is None) or (not sniffer_thread.is_alive()):
            sniffer_stop = False
            sniffer_thread = threading.Thread(target=self._scapy_sniffer)
            sniffer_thread.daemon = True
            sniffer_thread.start()
        stop_button.config(state=ACTIVE)

    def _stopper(self,start_button:Button, stop_button:Button):
        """
            Disables and enables the `stop button` and `start button`
            respectively and kills the live sniffing process.
        """
        global sniffer_stop
        stop_button.config(state=DISABLED)
        sniffer_stop = True
        start_button.config(state=ACTIVE)

    def _scapy_sniffer(self):
        global sniffer_stop
        sniff(iface='Realtek Gaming GbE Family Controller',prn=self._feature_extractor,stop_filter=self._stop_sniffing)
    
    def gui_init(self):
        """
            The function that start the GUI. Should be called in the end.
        """
        global textbox
        window = Tk()
        window.geometry('800x600')
        window.title("NIDSv2")
        header_frame = Frame(window,width=200,height=400,
                             highlightbackground='black',
                             highlightthickness=1)
        header_frame.grid(row=0,column=0,columnspan=2, 
                          padx=10,pady=5)
        header_label = Label(header_frame,text='Welcome To NIDSv2',
                      font=('Arial',20,'bold'),bg='red')
        header_label.grid(row=0,column=0,columnspan=2)

        left_frame = Frame(window,width=200, height=200,
                           highlightbackground='black',
                           highlightthickness=1)
        left_frame.grid(row=1,rowspan=3,column=0, padx=10, pady=5)
        textbox_label = Label(left_frame,text='Sniffer Logs:',
                              font=('Arial',8))
        textbox_label.grid(row=1,column=0)
        # textbox = Text(left_frame)
        # text_scroll = Scrollbar(left_frame)
        # text_scroll.config(command=textbox.yview)
        # textbox.config(state=DISABLED,yscrollcommand=text_scroll.set)
        # textbox.grid(row=2,column=0)
        # text_scroll.grid(row=2,column=1)
        textbox = scrolledtext.ScrolledText(left_frame,undo=True)
        textbox['font'] = ('consolas',12)
        textbox.config(state=DISABLED)
        textbox.grid(row=2,column=0)
        right_frame = Frame(window,width=100,height=200)
        right_frame.grid(row=1,column=3)
        # This is responsible to display our logs
        # Creating the start and stop buttons
        start_button = Button(right_frame,
                              text='Start NIDS',
                              font=('Arial',10),
                              state=ACTIVE)
        stop_button = Button(right_frame,
                              text='Stop NIDS',
                              font=('Arial',10),
                              state=DISABLED)
        start_button.config(command=lambda: self._starter(start_button,
                                                    stop_button))
        stop_button.config(command=lambda: self._stopper(start_button,
                                                   stop_button))
        start_button.grid()
        stop_button.grid()
        window.mainloop()

    def _flags_to_encode(self, tcp_flags: str) -> int:
        """
          Performs one-hot encoding on the tcp flags
        """
        if tcp_flags == '':
            return -1
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

    def _feature_extractor(self,packet):
          """
               Callback function passed to `prn` argument of scapy's
               sniff function. This function extracts the relevent features for our model.
          """
          global textbox

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
                self.packet_info.append(current_packet_info)

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
                self.packet_info.append(current_packet_info)

            try:
                # Predict the packet
                protocol = ''
                match current_packet_info['protocol']:
                    case 6:
                        protocol = 'tcp'
                    case 17:
                        protocol = 'udp'
                
                # If packet is UDP or TCP then send it's payload to yara for matching
                if protocol == 'udp' or protocol == 'tcp':
                    match protocol:
                        case 'tcp':
                            self.yara_rules_match(packet_payload=packet[TCP].payload)
                        case 'udp':
                            self.yara_rules_match(packet_payload=packet[UDP].payload)
                for dict in self.rule_dictionary:
                    if packet[IP].src == dict['ip'] and \
                        packet[protocol] and dict['state'] == 'allow':
                        continue
                    
                current_packet_info['flags'] = self._flags_to_encode(
                    tcp_flags=current_packet_info['flags']
                )
                df = pd.DataFrame([current_packet_info])
                prediction = self.dt_model.predict(df)
                if prediction != ['benign']:
                    match prediction[0]:
                        case 'nmap':
                            textbox.config(state=NORMAL)
                            textbox.insert(END,f'Possible {prediction[0]} scan from {packet[IP].src}'+"\n")
                            textbox.config(state=DISABLED)
                            logging.warning(f'Possible {prediction[0]} scan from {packet[IP].src}')
                        case 'ddos':
                            if protocol == 'udp':
                                textbox.config(state=NORMAL)
                                textbox.insert(END,f'Possible {prediction[0]} attack from {packet[IP].src} on port {packet[UDP].dport}'+"\n")
                                textbox.config(state=DISABLED)
                                logging.warning(f'Possible {prediction[0]} attack from {packet[IP].src} on port {packet[UDP].dport}')
                            elif protocol == 'tcp':
                                textbox.config(state=NORMAL)
                                textbox.insert(END,f'Possible {prediction[0]} attack from {packet[IP].src} on port {packet[TCP].dport}'+"\n")
                                textbox.config(state=DISABLED)
                                logging.warning(f'Possible {prediction[0]} attack from {packet[IP].src} on port {packet[TCP].dport}')

                    
            except UnboundLocalError:
                print('local var error')

if __name__ == '__main__':
    nids = NIDS()
    nids.gui_init()