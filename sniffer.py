import threading
from scapy.all import sniff
import tkinter as tk
from tkinter import ttk
from scapy.layers.inet import TCP, UDP

class SnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")

        self.packets = []
        self.sniffing = False
        self.sniffer_thread = None

        self.protos = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            41: "IPv6",
            89: "OSPF",
            132: "SCTP"
        }

        self.filter_vars = {}
        filter_frame = ttk.LabelFrame(root, text="Filter Protocols")
        filter_frame.pack(padx=10, pady=5, fill=tk.X)

        for proto_num, proto_name in self.protos.items():
            var = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(filter_frame, text=f"{proto_name} ({proto_num})", variable=var)
            cb.pack(side=tk.LEFT, padx=5)
            self.filter_vars[proto_num] = var

        ip_port_frame = ttk.LabelFrame(root, text="IP and Port Filter (substring match)")
        ip_port_frame.pack(padx=10, pady=5, fill=tk.X)

        ttk.Label(ip_port_frame, text="IP (src or dst):").pack(side=tk.LEFT, padx=5)
        self.ip_filter_entry = ttk.Entry(ip_port_frame, width=20)
        self.ip_filter_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(ip_port_frame, text="Port (src or dst):").pack(side=tk.LEFT, padx=5)
        self.port_filter_entry = ttk.Entry(ip_port_frame, width=10)
        self.port_filter_entry.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(pady=5)

        self.stop_btn = ttk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(pady=5)

        tree_frame = ttk.Frame(root)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Dodajemy kolumnę port
        self.tree = ttk.Treeview(tree_frame, columns=('src', 'dst', 'proto', 'port'), show='headings')
        self.tree.heading('src', text='Source IP')
        self.tree.heading('dst', text='Destination IP')
        self.tree.heading('proto', text='Protocol')
        self.tree.heading('port', text='Port')
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.v_scroll = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.v_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.v_scroll.set)

        self.tree.bind('<<TreeviewSelect>>', self.show_packet_details)

    def packet_matches_filters(self, packet):
        if not packet.haslayer('IP'):
            return False

        proto_num = packet.proto
        if proto_num not in self.filter_vars or not self.filter_vars[proto_num].get():
            return False

        ip_layer = packet['IP']
        ip_filter = self.ip_filter_entry.get().strip()
        if ip_filter:
            if ip_filter not in ip_layer.src and ip_filter not in ip_layer.dst:
                return False

        port_filter = self.port_filter_entry.get().strip()
        if port_filter:
            if packet.haslayer(TCP):
                sport = str(packet[TCP].sport)
                dport = str(packet[TCP].dport)
            elif packet.haslayer(UDP):
                sport = str(packet[UDP].sport)
                dport = str(packet[UDP].dport)
            else:
                return False

            if port_filter not in sport and port_filter not in dport:
                return False

        return True

    def get_ports(self, packet):
        if packet.haslayer(TCP):
            return f"{packet[TCP].sport} → {packet[TCP].dport}"
        elif packet.haslayer(UDP):
            return f"{packet[UDP].sport} → {packet[UDP].dport}"
        else:
            return ""

    def packet_callback(self, packet):
        if self.packet_matches_filters(packet):
            proto_name = self.protos.get(packet.proto, str(packet.proto))
            ip_layer = packet['IP']
            src = ip_layer.src
            dst = ip_layer.dst
            port_str = self.get_ports(packet)
            self.packets.append(packet)
            self.root.after(0, lambda: self.update_tree(src, dst, proto_name, port_str))

    def update_tree(self, src, dst, proto, port):
        item_id = self.tree.insert('', 'end', values=(src, dst, proto, port))
        self.tree.see(item_id)

    def show_packet_details(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        index = self.tree.index(selected[0])
        packet = self.packets[index]

        detail_win = tk.Toplevel(self.root)
        detail_win.title("Packet Details")

        text = tk.Text(detail_win, wrap='word', width=100, height=40)
        text.pack(fill=tk.BOTH, expand=True)

        details = packet.show(dump=True)
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)

    def start_sniffing(self):
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
        if self.sniffing:
            self.sniffing = False
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)

    def sniff_packets(self):
        sniff(prn=self.packet_callback, stop_filter=lambda x: not self.sniffing)

if __name__ == "__main__":
    root = tk.Tk()
    app = SnifferApp(root)
    root.mainloop()
