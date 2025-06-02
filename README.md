# NetRaptor - ARP Poisoning MITM Tool

NetRaptor is a GUI-based ARP poisoning tool built with Python that allows you to scan a network, select a target and gateway, and perform a Man-in-the-Middle (MITM) attack. This tool is designed for educational purposes and authorized network security testing only.

## Features

- **Network Scanning**: Scan for hosts on a specified network range.
- **Target and Gateway Selection**: Easily select a target and gateway IP from discovered devices or manually enter a gateway IP.
gateway ip is your router ipaddress

- **ARP Poisoning**: Perform ARP poisoning to initiate a MITM attack.
- **Packet Analysis with Wireshark**: Use Wireshark to capture and analyze network traffic.
- **User-Friendly GUI**: Built with Tkinter for easy interaction.
- **Stop ARP Poisoning**: Stop the attack at any time using the "Stop ARP Poisoning" button

## Tool Graphical User Interface:


![Screenshot 2024-11-06 212736](https://github.com/user-attachments/assets/7d0fac47-395d-4dcd-9a2d-58701d0dc7a3)



## Disclaimer

Warning: This tool is for educational purposes and authorized testing only. Unauthorized use is illegal and unethical. Ensure you have permission to test on any network before using this tool.

## Requirements
- **Python 3.x**
- **Scapy**: For network packet manipulation.
- **Tkinter**: For GUI (usually included with Python by default).
- **Wireshark (optional)**: For analyzing network packets

  
  ## Installation 

1. **Clone the Repository:**

  

  ```bash
  git clone https://github.com/s-r-e-e-r-a-j/NetRaptor.git
  ```
2. **Navigate to the NetRaptor directory**
  ```bash
  cd NetRaptor
  ```
3. **Install required libraries** 

```bash
pip3 install -r requirements.txt
  ```
  

4. **Navigate to the NetRaptor directory**:
 ```bash
  cd NetRaptor
  ```
5. **install the tool**
 ```bash
 sudo python3 install.py
  ```
   Then Type `y` for Install
   
 6. **Run the Tool:**
  ```bash
  sudo netraptor
```
## Instructions:

- **Enter Network Range**: Specify the network range (e.g., 192.168.1.0/24) to scan.
- **Scan for Hosts**: Click "Scan for Hosts" to discover devices on the network.
- **Select Target and Gateway**: Choose a target device and a gateway device from the dropdown menus, or manually enter a gateway IP if it’s not listed.gateway ip is your router ipaddress 
- **Start ARP Poisoning:** Click "Start ARP Poisoning" to initiate the attack.
- **Stop ARP Poisoning**: If you need to stop the attack, click the "Stop ARP Poisoning" button. This will safely terminate the ARP poisoning process.
- **Open Wireshark**: Launch Wireshark to capture and analyze network packets. Select the network interface in Wireshark and start capturing to observe the network traffic between the target and gateway. Look for ARP requests, replies, and other intercepted packets.
  
 ## GUI Overview

- **Title**: Displays "NetRaptor" as the tool name.
- **Network Range Input**: Enter the network range to scan.
- **Scan Button**: Begins network scanning to discover hosts.
- **Target Dropdown**: Lists discovered hosts for target selection.
- **Gateway Dropdown**: Lists discovered hosts for gateway selection or allows manual entry.gateway ip is your router ipaddress 
- **Start ARP Poisoning Button**: Starts the ARP poisoning attack on the selected target and gateway.
- **Stop ARP Poisoning Button**: Stops the ARP poisoning attack once it has started.
- **Wireshark**: Use Wireshark in parallel to monitor and analyze network traffic during the attack.

## uninstallation

```bash
cd NetRaptor
```
```bash
cd NetRaptor
```
```bash
sudo python3 install.py
```
Then Type `n` for uninstall

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Credits
Created by Sreeraj
