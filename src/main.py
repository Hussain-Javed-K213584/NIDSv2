from tkinter import *
from random import randint
from scapy.all import *
import multiprocessing
import threading

sniffer_stop = False
textbox = None
sniffer_thread = None

def _scapy_callback(pkt):
     global textbox
     print(pkt.summary())

def stop_sniffing(pkt):
     global sniffer_stop
     return sniffer_stop

def _scapy_sniffer():
     global sniffer_stop
     sniff(filter='tcp', prn=_scapy_callback,stop_filter=stop_sniffing)

def starter(start_button:Button,stop_button:Button):
     """
        Button command which disables the `start button`
        and enables the `stop button`. It also starts
        the live sniffing process by started another python process.
     """
     global sniffer_stop
     global sniffer_thread
     start_button.config(state=DISABLED)
     if (sniffer_thread is None) or (not sniffer_thread.is_alive()):
          sniffer_stop = False
          sniffer_thread = threading.Thread(target=_scapy_sniffer)
          sniffer_thread.daemon = True
          sniffer_thread.start()
     stop_button.config(state=ACTIVE)

def stopper(start_button:Button, stop_button:Button):
     """
        Disables and enables the `stop button` and `start button`
        respectively and kills the live sniffing process.
     """
     global sniffer_stop
     stop_button.config(state=DISABLED)
     sniffer_stop = True
     start_button.config(state=ACTIVE)

def gui_init():
        # Initialize the GUI
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
        textbox = Text(left_frame)
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
        start_button.config(command=lambda: starter(start_button,
                                                    stop_button))
        stop_button.config(command=lambda: stopper(start_button,
                                                   stop_button))
        start_button.grid()
        stop_button.grid()
        window.mainloop()

class NIDS:
    def __init__(self):
         pass
    

if __name__ == '__main__':
    gui_init()