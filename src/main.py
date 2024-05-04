from tkinter import *
import tkinter.scrolledtext as scrolledtext
from tkinter import ttk
import sv_ttk
from ttkthemes import ThemedTk
from scapy.all import *
from joblib import load
import threading
import os
import pandas as pd
import configparser
import yara
import logging
from itertools import zip_longest
from pprint import pprint
from platform import system
import re

if system() == 'Windows':
    from scapy.arch.windows import get_windows_if_list

sniffer_stop = False
textbox = None
sniffer_thread = None
menu = None

class NIDS:
    def __init__(self):
          src_path = os.path.dirname(os.path.abspath(__file__))
          file_path = os.path.join(src_path,'../model_training/dt_classifier.pkl')
          self.rule_file_path = os.path.join(src_path,'rules.conf')
          yara_dir = os.path.join(src_path, 'yara-rules')
          # store all yara files inside a list
          temp_yara_filenames = [file for file in os.listdir(yara_dir) if os.path.isfile(os.path.join(yara_dir,file))]
          self.yara_files = []
          for i in range(len(temp_yara_filenames)):
              self.yara_files.append(f'namepsace{i}')
              self.yara_files.append(os.path.join(yara_dir,temp_yara_filenames[i]))

            # I do not know what this does but I do know this helps in coverting list to a dict
          pairs = zip_longest(*[iter(self.yara_files)] * 2, fillvalue=None)
          self.yara_files = {key: value for key,value in pairs} 
          
          # Trying to delete temp variables
          del temp_yara_filenames
          del pairs
          self.dt_model = load(file_path)
          self.columns = [
           'dport', 'sport','protocol', 'flags', 'time bw prev packet','spkts','dpkts' ,'pkt_len','ttl', 'payload size'
          ]
          self.packet_info = []
          self.prev_packet_time = 0
          self.label = ''
          self.file_name = ''
          self.config_parser = configparser.ConfigParser()
          self.rule_dictionary = []
          # Get interface list based on operating system
          self.windows_if_list = None
          self.linux_if_list = None
          self.NETWORK_INTERFACE = ''
          self.local_pc_ip = get_if_addr(self.NETWORK_INTERFACE)
          if system() == 'Windows':
              self.windows_if_list = get_windows_if_list()
          elif system() == 'Linux':
              self.linux_if_list = get_if_list()
          logging.basicConfig(filename='alerts.log', filemode='a',format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')


    def yara_rules_match(self,packet_payload:bytes,pkt):
        """
        A function that takes in HTTP payload and runs it against
        the YARA rule to find a match. If a match is found against
        a yara rule then it is logged in `alerts.log`.

        Parameters
        ---
            packet_payload: HTTP packet of type bytes()
            pkt: The sniffed packet using scapy. Used to provide the IP address and port.
        
        returns
        ---
            Nothing
        """
        regex_url_pattern = r'\b(?:GET|POST)\s+([^\s?]+)'
        regex = re.compile(regex_url_pattern)
        rules = yara.compile(filepaths=self.yara_files)
        matcher = rules.match(data=packet_payload.decode())
        if matcher != {}:
            urls_found = regex.findall(packet_payload.decode())
            for _, key in enumerate(matcher):
                for dict in matcher[key]:
                    if dict['matches'] == True:
                        print(f'yara rule matched on {dict["rule"]}')
                        textbox.config(state=NORMAL)
                        textbox.insert(END,f"Possible {dict['rule']} being performed on host port {pkt[IP].dport} by {pkt[IP].src} on endpoint {urls_found[0]}\n")
                        logging.warning(f"Possible {dict['rule']} being performed on host port {pkt[IP].dport} by {pkt[IP].src} on endpoint {urls_found[0]}") 
                        textbox.config(state=DISABLED)
        return

    # TODO: Test that this function works as intended.
    def rule_parser(self):
        """
            Parses a config file on allow and deny requests
        """
        self.config_parser.read(self.rule_file_path)
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
                'protocol':proto_list[i],
                'state':state_list[i]
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
            It also reloads the rules.
        """
        global sniffer_stop
        global sniffer_thread
        global menu

        # First thing is to set the correct network interface and get the correct host IP address
        self.NETWORK_INTERFACE = menu.get().strip() # Strip removes the leading trailing whitespace I left for padding
        self.local_pc_ip = get_if_addr(self.NETWORK_INTERFACE)
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
        global sniffer_thread
        stop_button.config(state=DISABLED)
        sniffer_stop = True
        start_button.config(state=ACTIVE)
        self.rule_dictionary.clear()

    def _get_iface(self) -> str:
        """
            Returns the interface on each call. Used by scapy.sniff
        """
        return self.NETWORK_INTERFACE

    def _scapy_sniffer(self):
        global sniffer_stop
        sniff(iface=self._get_iface(),prn=self._feature_extractor,stop_filter=self._stop_sniffing)
    
    def gui_init(self):
        """
            The function that start the GUI. Should be called in the end.
        """
        global textbox
        global menu
        window = Tk()
        style = None
        if system() == 'Linux':
            style = ttk.Style(window)
            style.theme_use('clam')
        window.geometry('1024x768')
        window.title("NIDSv2")
        header_frame = ttk.Frame(window,width=200,height=400)
        header_frame.grid(row=0,column=0,columnspan=2, 
                          padx=10,pady=5)
        header_label = ttk.Label(header_frame,text='Welcome To NIDSv2',
                      font=('Arial',20,'bold'))
        header_label.grid(row=0,column=0,columnspan=2)

        left_frame = ttk.Frame(window,width=200, height=200)
        left_frame.grid(row=1,rowspan=3,column=0, padx=10, pady=5)
        textbox_label = ttk.Label(left_frame,text='Sniffer Logs:',
                              font=('Arial',8))
        textbox_label.grid(row=1,column=0)

        y_scroll = ttk.Scrollbar(left_frame)
        textbox = Text(left_frame, yscrollcommand=y_scroll.set,width=100,height=30)
        y_scroll.grid(sticky='ns')
        y_scroll.config(command=textbox.yview)
        textbox.config(state=DISABLED)
        textbox.grid(row=2,column=0)

        # This is responsible to display our logs
        right_frame = ttk.Frame(window,width=100,height=200)
        right_frame.grid(row=2,column=5, padx=20,pady=20)
        
        # Creating the start and stop buttons
        start_button = ttk.Button(right_frame,
                              text='Start NIDS',
                              state=ACTIVE)
        stop_button = ttk.Button(right_frame,
                              text='Stop NIDS',
                              state=DISABLED)
        start_button.config(command=lambda: self._starter(start_button,
                                                    stop_button))
        stop_button.config(command=lambda: self._stopper(start_button,
                                                   stop_button))
        start_button.grid(padx=10,pady=10)
        stop_button.grid(padx=10,pady=10)

        bottom_frame = ttk.Frame(window, width=300,height=100)
        bottom_frame.grid(row=3)
        # Set the options for the menu
        menu = StringVar()
        menu.set("Select the network interface  ")
        interface_options = []
        if system() == 'Windows':
            for dict in self.windows_if_list:
                if dict['mac'] != '':
                    interface_options.append(dict['description'] + '  ')
        elif system() == 'Linux':
            for interface in self.linux_if_list:
                interface_options.append(interface)

        # Creating the dropdown menu
        dropdown = ttk.OptionMenu(window, menu,*interface_options)
        dropdown.grid()

        # Set theme only if OS is windows
        if system() == 'Windows':
            sv_ttk.set_theme("dark")
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
                
                match protocol:
                    case 'tcp':
                        for dict in self.rule_dictionary:
                            if (packet[IP].src == dict['ip']) and \
                                (packet.haslayer(TCP) and dict['state'] == 'allow') \
                                    and (packet[IP].dst == self.local_pc_ip):
                                return
                    case 'udp':
                        for dict in self.rule_dictionary:
                            if packet[IP].src == dict['ip'] and \
                                packet.haslayer(UDP) and dict['state'] == 'allow'\
                                    and (packet[IP].dst == self.local_pc_ip):
                                return
                
                # If packet has HTTP layer then send it's payload to yara for matching
                if protocol == 'tcp' and packet[TCP].dport == 80:
                    # TODO: Hussain, do yara matching in another thread please
                    http_payload = bytes(packet[TCP].payload)
                    yara_thread = threading.Thread(target=self.yara_rules_match, args=(http_payload,packet,))
                    # self.yara_rules_match(http_payload,packet) 
                    yara_thread.daemon = True
                    yara_thread.start()
                    
                current_packet_info['flags'] = self._flags_to_encode(
                    tcp_flags=current_packet_info['flags']
                )
                df = pd.DataFrame([current_packet_info])
                prediction = self.dt_model.predict(df)
                print(f"dst: {packet[IP].dst} -> local: {self.local_pc_ip}")
                # This statement fixes the issue of false positives by a fuckton

                # TODO: Limit the amount of output that comes on the display box.
                # TODO: Add timestamp to output logs as well.
                if prediction != ['benign'] and packet[IP].dst == self.local_pc_ip:
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