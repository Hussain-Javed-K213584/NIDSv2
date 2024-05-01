from tkinter import *
from random import randint
from scapy.all import *
import multiprocessing

running_processes = []

def _scapy_sniffer():
     sniff(filter='tcp', prn=lambda x: x.summary())

def starter(start_button:Button,stop_button:Button):
     global running_processes
     start_button.config(state=DISABLED)
     proc = multiprocessing.Process(target=_scapy_sniffer,
                                    args=())
     proc.start()
     running_processes.append(proc)
     stop_button.config(state=ACTIVE)
def stopper(start_button:Button, stop_button:Button):
     global running_processes
     stop_button.config(state=DISABLED)
     start_button.config(state=ACTIVE)
     for process in running_processes:
          process.terminate()

def gui_init():
        # Initialize the GUI
        window = Tk()
        window.geometry('800x600')
        window.title("NIDSv2")
        # This is responsible to display our logs
        label = Label(window,text='Welcome To NIDSv2',
                      font=('Arial',20,'bold'))
        label.pack()
        # Creating the start and stop buttons
        start_button = Button(window,
                              text='Start NIDS',
                              font=('Arial',10),
                              state=ACTIVE)
        stop_button = Button(window,
                              text='Stop NIDS',
                              
                              font=('Arial',10),
                              state=DISABLED)
        start_button.config(command=lambda: starter(start_button,
                                                    stop_button))
        stop_button.config(command=lambda: stopper(start_button,
                                                   stop_button))
        start_button.pack()
        stop_button.pack()
        window.mainloop()

class NIDS:
    def __init__(self):
         pass
    

if __name__ == '__main__':
    gui_init()