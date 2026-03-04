import logging
import ipaddress
from datetime import datetime
from collections import defaultdict

# Configuration for anomaly detection
ANOMALY_CONFIG = {
    'port_scan': {'time_window': 60, 'threshold': 10},
    'dos': {'time_window': 60, 'threshold': 10},
    'brute_force': {'time_window': 300, 'threshold': 50},
    'unauthorized_access': {'time_window': 60, 'threshold': 5},
    'invalid_tcp_flags': {'time_window': 60, 'threshold': 5},
    'unusual_traffic': {'time_window': 3600, 'threshold': 1000},
    'unusual_packet_size': {'time_window': 60, 'threshold': 10000},
}

# Buffers for tracking activities
port_scan_buffer = defaultdict(list)
dos_buffer = defaultdict(list)
brute_force_buffer = defaultdict(list)
unauthorized_access_buffer = defaultdict(list)
invalid_tcp_flags_buffer = defaultdict(list)
unusual_traffic_buffer = defaultdict(list)
unusual_packet_size_buffer = defaultdict(list)

# Trusted networks (CIDR notation)
TRUSTED_NETWORKS = [
    ipaddress.ip_network('127.0.0.1/32'),
    ipaddress.ip_network('192.168.1.0/24'),
    ipaddress.ip_network('172.17.243.0/24'),
    ipaddress.ip_network('172.17.240.0/24'),
    ipaddress.ip_network('172.17.241.0/24'),
    ipaddress.ip_network('172.17.242.0/24')
]

# Multicast networks to ignore for unauthorized detection
MULTICAST_NETWORK = ipaddress.ip_network('224.0.0.0/4')


def parse_log_line(line):
    """Parse a firewall log line into a dictionary."""
    try:
        parts = line.strip().split()
        if len(parts) < 8:
            return None
        timestamp = datetime.strptime(f"{parts[0]} {parts[1]}", '%Y-%m-%d %H:%M:%S')
        return {
            'timestamp': timestamp,
            'action': parts[2],
            'protocol': parts[3],
            'src-ip': parts[4],
            'dst-ip': parts[5],
            'src-port': parts[6],
            'dst-port': parts[7],
            'size': int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else 0,
            'tcpflags': parts[9] if len(parts) > 9 else '-',
            'tcpsyn': parts[10] if len(parts) > 10 else '-',
            'tcpack': parts[11] if len(parts) > 11 else '-',
        }
    except Exception as e:
        logging.error(f"Error parsing log line: {e}")
        return None


def is_trusted_ip(ip):
    """Return True if IP is in any trusted network."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in net for net in TRUSTED_NETWORKS)
    except ValueError:
        return False


def detect_anomalies(entry):
    """Run all checks on a parsed log entry and return list of alerts."""
    if not entry:
        return []

    alerts = []
    ts = entry['timestamp']
    src = entry['src-ip']
    dst = entry['dst-ip']
    action = entry['action']
    proto = entry['protocol']
    syn = entry['tcpsyn']
    ack = entry['tcpack']
    flags = entry['tcpflags']
    sport = entry['src-port']
    dport = entry['dst-port']
    size = entry['size']

    # Port scan
    a = check_port_scan(src, dst, ts, dport)
    if a: alerts.append(a)
    # DoS
    a = check_dos(dst, dport, ts, src, proto, syn)
    if a: alerts.append(a)
    # Brute force
    a = check_brute_force(src, dport, ts, action, proto, syn, ack)
    if a: alerts.append(a)
    # Unauthorized access (skip trusted or multicast)
    if not is_trusted_ip(src) and ipaddress.ip_address(dst) not in MULTICAST_NETWORK:
        a = check_unauthorized_access(src, dst, ts, proto)
        if a: alerts.append(a)
    # Invalid TCP flags
    a = check_invalid_tcp_flags(src, proto, ts, syn, ack, flags)
    if a: alerts.append(a)
    # Unusual traffic
    a = check_unusual_traffic(src, ts)
    if a: alerts.append(a)
    # Unusual packet size
    a = check_unusual_packet_size(src, ts, size)
    if a: alerts.append(a)

    return alerts

# --- existing checks unchanged ---
def check_port_scan(src_ip, dst_ip, timestamp, dst_port):
    try:
        port_scan_buffer[src_ip].append((timestamp, dst_port))
        port_scan_buffer[src_ip] = [(t,p) for t,p in port_scan_buffer[src_ip]
                                     if (timestamp - t).total_seconds() <= ANOMALY_CONFIG['port_scan']['time_window']]
        if len({p for _,p in port_scan_buffer[src_ip]}) >= ANOMALY_CONFIG['port_scan']['threshold']:
            return {'type':'Port Scan','message':f"Possible port scan from {src_ip} to {dst_ip}",
                    'timestamp':timestamp.strftime('%Y-%m-%d %H:%M:%S'),'src-ip':src_ip,'dst-ip':dst_ip}
    except Exception as e:
        logging.error(f"check_port_scan error: {e}")
    return None

def check_dos(dst_ip, dst_port, timestamp, src_ip, protocol, tcpsyn):
    """Detect DoS activity."""
    try:
        current_time = timestamp
        dos_buffer[dst_ip].append((current_time, src_ip, protocol, tcpsyn))
        dos_buffer[dst_ip] = [
            (t, s, p, syn) for t, s, p, syn in dos_buffer[dst_ip]
            if (current_time - t).total_seconds() <= ANOMALY_CONFIG['dos']['time_window']
        ]
        if len(dos_buffer[dst_ip]) >= ANOMALY_CONFIG['dos']['threshold']:
            return {
                'type': 'DoS Attack',
                'message': f"Possible DoS attack on {dst_ip}:{dst_port} from {src_ip}",
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'src-ip': src_ip,
                'dst-ip': dst_ip
            }
        return None
    except Exception as e:
        logging.error(f"Error in check_dos: {e}")
        return None

def check_brute_force(src_ip, dst_port, timestamp, action, protocol, tcpsyn, tcpack):
    """Detect brute force activity."""
    try:
        current_time = timestamp
        if action == 'DROP' and protocol == 'TCP' and tcpsyn == '1' and tcpack == '0':
            brute_force_buffer[src_ip].append(current_time)
            brute_force_buffer[src_ip] = [
                t for t in brute_force_buffer[src_ip]
                if (current_time - t).total_seconds() <= ANOMALY_CONFIG['brute_force']['time_window']
            ]
            if len(brute_force_buffer[src_ip]) >= ANOMALY_CONFIG['brute_force']['threshold']:
                return {
                    'type': 'Brute Force',
                    'message': f"Possible brute force from {src_ip} on port {dst_port}",
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'src-ip': src_ip,
                    'dst-port': dst_port
                }
        return None
    except Exception as e:
        logging.error(f"Error in check_brute_force: {e}")
        return None

def check_unauthorized_access(src_ip, dst_ip, timestamp, protocol):
    """Detect unauthorized access attempts."""
    try:
        current_time = timestamp
        unauthorized_access_buffer[src_ip].append(current_time)
        unauthorized_access_buffer[src_ip] = [
            t for t in unauthorized_access_buffer[src_ip]
            if (current_time - t).total_seconds() <= ANOMALY_CONFIG['unauthorized_access']['time_window']
        ]
        if len(unauthorized_access_buffer[src_ip]) >= ANOMALY_CONFIG['unauthorized_access']['threshold']:
            return {
                'type': 'Unauthorized Access',
                'message': f"Possible unauthorized access from {src_ip} to {dst_ip}",
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'src-ip': src_ip,
                'dst-ip': dst_ip
            }
        return None
    except Exception as e:
        logging.error(f"Error in check_unauthorized_access: {e}")
        return None

def check_invalid_tcp_flags(src_ip, protocol, timestamp, tcpsyn, tcpack, tcpflags):
    """Detect invalid TCP flags."""
    try:
        current_time = timestamp
        if protocol == 'TCP' and tcpflags == '-' and (tcpsyn != '1' or tcpack != '1'):
            invalid_tcp_flags_buffer[src_ip].append(current_time)
            invalid_tcp_flags_buffer[src_ip] = [
                t for t in invalid_tcp_flags_buffer[src_ip]
                if (current_time - t).total_seconds() <= ANOMALY_CONFIG['invalid_tcp_flags']['time_window']
            ]
            if len(invalid_tcp_flags_buffer[src_ip]) >= ANOMALY_CONFIG['invalid_tcp_flags']['threshold']:
                return {
                    'type': 'Invalid TCP Flags',
                    'message': f"Invalid TCP flags detected from {src_ip}",
                    'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                    'src-ip': src_ip
                }
        return None
    except Exception as e:
        logging.error(f"Error in check_invalid_tcp_flags: {e}")
        return None

def check_unusual_traffic(src_ip, timestamp):
    """Detect unusual traffic patterns."""
    try:
        current_time = timestamp
        unusual_traffic_buffer[src_ip].append(current_time)
        unusual_traffic_buffer[src_ip] = [
            t for t in unusual_traffic_buffer[src_ip]
            if (current_time - t).total_seconds() <= ANOMALY_CONFIG['unusual_traffic']['time_window']
        ]
        if len(unusual_traffic_buffer[src_ip]) >= ANOMALY_CONFIG['unusual_traffic']['threshold']:
            return {
                'type': 'Unusual Traffic',
                'message': f"Unusual traffic volume from {src_ip}",
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'src-ip': src_ip
            }
        return None
    except Exception as e:
        logging.error(f"Error in check_unusual_traffic: {e}")
        return None

def check_unusual_packet_size(src_ip, timestamp, size):
    """Detect unusual packet sizes."""
    try:
        current_time = timestamp
        unusual_packet_size_buffer[src_ip].append((current_time, size))
        unusual_packet_size_buffer[src_ip] = [
            (t, s) for t, s in unusual_packet_size_buffer[src_ip]
            if (current_time - t).total_seconds() <= ANOMALY_CONFIG['unusual_packet_size']['time_window']
        ]
        total_size = sum(s for _, s in unusual_packet_size_buffer[src_ip])
        if total_size >= ANOMALY_CONFIG['unusual_packet_size']['threshold']:
            return {
                'type': 'Unusual Packet Size',
                'message': f"Unusual packet size from {src_ip} (total: {total_size} bytes)",
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S'),
                'src-ip': src_ip
            }
        return None
    except Exception as e:
        logging.error(f"Error in check_unusual_packet_size: {e}")
        return None