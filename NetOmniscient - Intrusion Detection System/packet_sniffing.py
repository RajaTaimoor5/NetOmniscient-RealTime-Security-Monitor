import scapy.all as scapy
import logging
import os
import subprocess
import threading
import psutil
from datetime import datetime
from collections import deque

# Configuration
MAX_SNIFFED_PACKETS = 100
LOG_FILE = 'netomniscient.log'
LOG_DIR = os.path.join(os.path.expanduser('~'), 'NetOmniscient_Logs')
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, LOG_FILE)

# Global variables
network_interface = ''
sniffing_enabled = False
sniffed_packets = deque(maxlen=MAX_SNIFFED_PACKETS)
_sniffer_thread = None
_stop_sniffing_event = threading.Event()

def enable_firewall_logging(log_path):
    """Enable Windows Firewall logging to the specified log path."""
    try:
        log_dir = os.path.dirname(log_path)
        os.makedirs(log_dir, exist_ok=True)
        cmd = (
            f'netsh advfirewall set allprofiles logging filename "{log_path}" '
            f'maxfilesize 32767 droppedconnections enable allowedconnections enable'
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"Failed to enable firewall logging: {result.stderr}")
            print(f"❌ Failed to enable firewall logging: {result.stderr}")
            return False
        logging.info(f"Firewall logging enabled at {log_path}")
        print(f"✅ Firewall logging enabled at {log_path}")
        return True
    except PermissionError:
        logging.error(f"Permission denied enabling firewall logging for {log_path}")
        print(f"❌ Permission denied enabling firewall logging for {log_path}")
        return False
    except Exception as e:
        logging.error(f"Error enabling firewall logging: {e}")
        print(f"❌ Error enabling firewall logging: {e}")
        return False

def get_active_interface():
    """Get the active network interface's friendly name."""
    try:
        net_if_stats = psutil.net_if_stats()
        logging.debug(f"psutil interfaces: {net_if_stats}")
        print(f"📡 psutil interfaces: {net_if_stats}")
        for iface in net_if_stats:
            if net_if_stats[iface].isup and iface.lower() not in ["loopback", "Loopback Pseudo-Interface 1"]:
                try:
                    addrs = psutil.net_if_addrs()[iface]
                    for addr in addrs:
                        if addr.family == psutil.AF_LINK:
                            logging.info(f"Active interface found: {iface}")
                            print(f"✅ Active interface found: {iface}")
                            return iface
                except KeyError:
                    continue
        logging.warning("No active interface found")
        print("⚠️ No active interface found")
        return None
    except Exception as e:
        logging.error(f"Error getting active interface: {e}")
        print(f"❌ Error getting active interface: {e}")
        return None

def packet_callback(packet):
    """Callback function to process sniffed packets."""
    if not sniffing_enabled or _stop_sniffing_event.is_set():
        return
    try:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = packet[scapy.IP].src if scapy.IP in packet else '-'
        dst_ip = packet[scapy.IP].dst if scapy.IP in packet else '-'
        protocol = packet[scapy.IP].proto if scapy.IP in packet else '-'
        src_port = packet[scapy.TCP].sport if scapy.TCP in packet else (packet[scapy.UDP].sport if scapy.UDP in packet else '-')
        dst_port = packet[scapy.TCP].dport if scapy.TCP in packet else (packet[scapy.UDP].dport if scapy.UDP in packet else '-')
        size = len(packet)
        protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        protocol_name = protocol_map.get(protocol, str(protocol))
        packet_data = {
            'timestamp': timestamp,
            'src-ip': src_ip,
            'dst-ip': dst_ip,
            'src-port': str(src_port),
            'dst-port': str(dst_port),
            'protocol': protocol_name,
            'size': str(size)
        }
        sniffed_packets.append(packet_data)
        logging.debug(f"Sniffed packet: {packet_data}")
        print(f"📡 Sniffed packet: {packet_data}")
    except Exception as e:
        logging.error(f"Error processing packet: {e}")
        print(f"❌ Error processing packet: {e}")

def start_sniffing(interface):
    """Start packet sniffing on the specified interface."""
    global sniffing_enabled, _sniffer_thread, network_interface
    try:
        if not interface:
            logging.error("No network interface specified")
            print("❌ No network interface specified")
            return False
        if sniffing_enabled:
            stop_sniffing()
        network_interface = interface
        sniffing_enabled = True
        _stop_sniffing_event.clear()
        logging.debug(f"Starting scapy.sniff on interface: {interface}")
        print(f"📡 Starting scapy.sniff on interface: {interface}")
        _sniffer_thread = threading.Thread(
            target=scapy.sniff,
            kwargs={
                'iface': interface,
                'filter': 'ip',
                'prn': packet_callback,
                'store': False,
                'stop_filter': lambda x: _stop_sniffing_event.is_set()
            }
        )
        _sniffer_thread.daemon = True
        _sniffer_thread.start()
        logging.info(f"Started sniffing on {interface}")
        print(f"✅ Started sniffing on {interface}")
        return True
    except Exception as e:
        logging.error(f"Error starting sniffing on {interface}: {e}")
        print(f"❌ Error starting sniffing on {interface}: {e}")
        sniffing_enabled = False
        network_interface = ''
        return False

def stop_sniffing():
    """Stop packet sniffing."""
    global sniffing_enabled, _sniffer_thread
    try:
        if sniffing_enabled:
            _stop_sniffing_event.set()
            if _sniffer_thread:
                _sniffer_thread.join(timeout=2.0)
            sniffing_enabled = False
            _sniffer_thread = None
            logging.info("Stopped sniffing")
            print("✅ Stopped sniffing")
    except Exception as e:
        logging.error(f"Error stopping sniffing: {e}")
        print(f"❌ Error stopping sniffing: {e}")
    finally:
        sniffing_enabled = False