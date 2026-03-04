import time
import logging
from datetime import datetime
from packet_sniffing import sniffed_packets
from attack_detection import (
    is_trusted_ip, check_port_scan, check_dos, check_brute_force,
    check_unauthorized_access, check_invalid_tcp_flags, check_unusual_traffic,
    check_unusual_packet_size
)

def background_task(monitor, socketio, recent_logs):
    """Process log entries, packets, and alerts, emitting them to clients in batches."""
    last_heartbeat = time.time()
    log_buffer = []
    alert_buffer = []
    last_log_emit = time.time()
    last_packet_emit = time.time()
    last_alert_emit = time.time()
    MAX_RECENT_LOGS = 100
    BATCH_EMIT_INTERVAL = 3
    MAX_LOGS_PER_BATCH = 50
    MAX_PACKETS_PER_BATCH = 50
    ALERT_AGGREGATION_WINDOW = 5

    while True:
        try:
            current_time = time.time()
            # Heartbeat
            if current_time - last_heartbeat > 10:
                socketio.emit('heartbeat', {'message': 'Server alive', 'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')})
                logging.info("Emitted heartbeat")
                print(f"📡 Emitted heartbeat")
                last_heartbeat = current_time

            # Process log entries
            if not monitor.log_queue.empty():
                log_entry = monitor.log_queue.get_nowait()
                log_entry_serializable = {
                    'timestamp': log_entry['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'src-ip': log_entry['src-ip'],
                    'dst-ip': log_entry['dst-ip'],
                    'src-port': log_entry['src-port'],
                    'dst-port': log_entry['dst-port'],
                    'protocol': log_entry['protocol'],
                    'action': log_entry['action'],
                    'size': log_entry['size']
                }
                log_buffer.append(log_entry_serializable)
                recent_logs.append(log_entry_serializable)
                if len(recent_logs) > MAX_RECENT_LOGS:
                    recent_logs.pop(0)

                if not is_trusted_ip(log_entry['src-ip']):
                    for check in [
                        lambda: check_port_scan(log_entry['src-ip'], log_entry['dst-ip'], log_entry['timestamp'], log_entry['dst-port']),
                        lambda: check_dos(log_entry['dst-ip'], log_entry['dst-port'], log_entry['timestamp'], log_entry['src-ip'], log_entry['protocol'], log_entry['tcpsyn']),
                        lambda: check_brute_force(
                            log_entry['src-ip'], log_entry['dst-port'], log_entry['timestamp'],
                            log_entry['action'], log_entry['protocol'], log_entry['tcpsyn'], log_entry['tcpack']
                        ),
                        lambda: check_unauthorized_access(log_entry['src-ip'], log_entry['dst-ip'], log_entry['timestamp'], log_entry['protocol']),
                        lambda: check_invalid_tcp_flags(
                            log_entry['src-ip'], log_entry['protocol'], log_entry['timestamp'],
                            log_entry['tcpsyn'], log_entry['tcpack'], log_entry['tcpflags']
                        ),
                        lambda: check_unusual_traffic(log_entry['src-ip'], log_entry['timestamp']),
                        lambda: check_unusual_packet_size(log_entry['src-ip'], log_entry['timestamp'], log_entry['size'])
                    ]:
                        alert = check()
                        if alert:
                            alert_buffer.append(alert)
                            logging.info(f"Buffered alert: {alert}")
                            print(f"📡 Buffered alert: {alert}")

            # Emit logs in batches
            if current_time - last_log_emit >= BATCH_EMIT_INTERVAL and log_buffer:
                batch = log_buffer[:MAX_LOGS_PER_BATCH]
                socketio.emit('new_log_batch', batch)
                logging.info(f"Emitted {len(batch)} logs in batch")
                print(f"📡 Emitted {len(batch)} logs in batch")
                log_buffer = log_buffer[MAX_LOGS_PER_BATCH:]
                last_log_emit = current_time

            # Emit packets in batches
            if sniffed_packets and current_time - last_packet_emit >= BATCH_EMIT_INTERVAL:
                packet_batch = list(sniffed_packets)[:MAX_PACKETS_PER_BATCH]
                socketio.emit('new_packet_batch', packet_batch)
                logging.info(f"Emitted {len(packet_batch)} packets in batch")
                print(f"📡 Emitted {len(packet_batch)} packets in batch")
                last_packet_emit = current_time

            # Emit aggregated alerts
            if current_time - last_alert_emit >= ALERT_AGGREGATION_WINDOW and alert_buffer:
                socketio.emit('alert_batch', alert_buffer)
                logging.info(f"Emitted {len(alert_buffer)} alerts in batch")
                print(f"📡 Emitted {len(alert_buffer)} alerts in batch")
                alert_buffer.clear()
                last_alert_emit = current_time

            time.sleep(0.1)
        except Exception as e:
            logging.error(f"Background task error: {e}")
            print(f"❌ Background task error: {e}")
            time.sleep(1)