# sniffer_gui.py

import threading
from scapy.all import sniff
import tkinter as tk
from tkinter import ttk

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")

        self.packets = []            # Store captured packets info
        self.sniffing = False        # Flag to control sniffing state
        self.sniffer_thread = None   # Thread for packet sniffing


        self.start_btn = ttk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(pady=5)


        self.stop_btn = ttk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(pady=5)


        self.tree = ttk.Treeview(root, columns=('src', 'dst', 'proto'), show='headings')
        self.tree.heading('src', text='Source IP')
        self.tree.heading('dst', text='Destination IP')
        self.tree.heading('proto', text='Protocol')
        self.tree.pack(fill=tk.BOTH, expand=True)

    def packet_callback(self, packet):
        """
        Called for each captured packet.
        Extract IP layer info and protocol number,
        convert protocol number to name,
        store info and update GUI.
        """
        if packet.haslayer('IP'):
            ip_layer = packet['IP']
            proto = packet.proto
            src = ip_layer.src
            dst = ip_layer.dst
            proto_name = self.proto_num_to_name(proto)
            self.packets.append((src, dst, proto_name))

            self.root.after(0, self.update_tree)

    def proto_num_to_name(self, proto_num):
        """
        Map common protocol numbers to their names.
        """
        protos = {1: "ICMP", 6: "TCP", 17: "UDP"}
        return protos.get(proto_num, str(proto_num))

    def update_tree(self):
        """
        Insert the latest captured packet info into the GUI list.
        """
        if self.packets:
            src, dst, proto = self.packets[-1]
            self.tree.insert('', 'end', values=(src, dst, proto))

    def start_sniffing(self):
        """
        Start sniffing packets in a separate thread.
        Clear previous data and update button states.
        """
        if not self.sniffing:
            self.sniffing = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            self.packets.clear()

            for item in self.tree.get_children():
                self.tree.delete(item)

            self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniffer_thread.start()

    def stop_sniffing(self):
        """
        Stop the packet sniffing process and update buttons.
        """
        if self.sniffing:
            self.sniffing = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def sniff_packets(self):
        """
        Capture packets continuously until sniffing flag is False.
        Uses scapy.sniff with stop_filter lambda.
        """
        sniff(prn=self.packet_callback, stop_filter=lambda x: not self.sniffing)

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()
