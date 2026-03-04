from flask import render_template, request
from flask_socketio import emit
import os
import logging
import threading
from packet_sniffing import sniffing_enabled, network_interface, get_active_interface, start_sniffing, stop_sniffing
from firewall_monitor import LogMonitor

def setup_gui(app, socketio, monitor, recent_logs):
    """Set up Flask routes and SocketIO handlers."""
    @app.route('/')
    def index():
        """Serve the GUI."""
        try:
            return render_template('GUI.html')
        except Exception as e:
            logging.error(f"Error rendering GUI.html: {e}")
            print(f"❌ Error rendering GUI.html: {e}")
            return f"Error rendering GUI: {str(e)}", 500

    @socketio.on('connect')
    def handle_connect():
        """Send buffered logs and packets to new clients."""
        try:
            logging.info("Client connected")
            print("📡 Client connected")
            for log in recent_logs:
                emit('new_log', log, room=request.sid)
            emit('config', {
                'log_path': monitor.log_path,
                'network_interface': network_interface,
                'available_interfaces': [get_active_interface()] if get_active_interface() else []
            }, room=request.sid)
        except Exception as e:
            logging.error(f"Error handling client connection: {e}")
            print(f"❌ Error handling client connection: {e}")
            emit('alert', {'type': 'System Error', 'message': f"Error connecting: {str(e)}"}, room=request.sid)

    @socketio.on('test_event')
    def handle_test_event(data):
        """Handle test events from clients."""
        try:
            logging.info(f"Received test_event: {data}")
            print(f"📡 Received test_event: {data}")
            emit('test_response', {'message': 'Server received test event'})
        except Exception as e:
            logging.error(f"Error handling test event: {e}")
            print(f"❌ Error handling test event: {e}")
            emit('alert', {'type': 'System Error', 'message': f"Test event error: {str(e)}"})

    @socketio.on('update_config')
    def handle_update_config(data):
        """Update the log file path and network interface."""
        try:
            new_log_path = data.get('log_path', '').strip()
            new_network_interface = data.get('network_interface', '').strip()

            if new_log_path:
                if not os.path.isabs(new_log_path):
                    emit('config_response', {'status': 'error', 'message': 'Log file path must be absolute'})
                    socketio.emit('alert', {'type': 'System Error', 'message': 'Log file path must be absolute'})
                    return
                if not os.path.exists(os.path.dirname(new_log_path)):
                    emit('config_response', {'status': 'error', 'message': 'Log file directory does not exist'})
                    socketio.emit('alert', {'type': 'System Error', 'message': 'Log file directory does not exist'})
                    return
                logging.info(f"Updating log path to: {new_log_path}")
                print(f"📡 Updating log path to: {new_log_path}")
                monitor.stop()
                monitor.__init__(new_log_path)
                observer_thread = threading.Thread(target=monitor.start)
                observer_thread.daemon = True
                observer_thread.start()
                emit('config_response', {'status': 'success', 'message': f"Log file path updated to {new_log_path}"})
                socketio.emit('alert', {'type': 'System Info', 'message': f"Log file path updated to {new_log_path}"})

            if new_network_interface:
                available_interfaces = [get_active_interface()] if get_active_interface() else []
                if not available_interfaces:
                    emit('config_response', {'status': 'error', 'message': 'No network interfaces available'})
                    socketio.emit('alert', {'type': 'System Error', 'message': 'No network interfaces available'})
                    return
                if new_network_interface not in available_interfaces:
                    emit('config_response', {'status': 'error', 'message': f"Invalid network interface: {new_network_interface}"})
                    socketio.emit('alert', {'type': 'System Error', 'message': f"Invalid network interface: {new_network_interface}"})
                    return
                stop_sniffing()
                start_sniffing(new_network_interface)
                emit('config_response', {'status': 'success', 'message': f"Packet sniffing enabled on {new_network_interface}"})
                socketio.emit('alert', {'type': 'System Info', 'message': f"Packet sniffing enabled on {new_network_interface}"})
            elif new_network_interface == '':
                stop_sniffing()
                emit('config_response', {'status': 'success', 'message': 'Packet sniffing disabled'})
                socketio.emit('alert', {'type': 'System Info', 'message': 'Packet sniffing disabled'})

        except Exception as e:
            logging.error(f"Error updating config: {e}")
            print(f"❌ Error updating config: {e}")
            emit('config_response', {'status': 'error', 'message': f"Error updating config: {str(e)}"})
            socketio.emit('alert', {'type': 'System Error', 'message': f"Error updating config: {str(e)}"})

    @socketio.on('reprocess_logs')
    def handle_reprocess_logs(data):
        """Reprocess the log file upon GUI request."""
        try:
            logging.info("Received reprocess_logs request")
            print("📡 Received reprocess_logs request")
            monitor.last_position = 0
            monitor.read_existing_lines()
            emit('config_response', {'status': 'success', 'message': 'Log file reprocessed'})
            socketio.emit('alert', {'type': 'System Info', 'message': 'Log file reprocessed successfully'})
        except Exception as e:
            logging.error(f"Error reprocessing log file: {e}")
            print(f"❌ Error reprocessing log file: {e}")
            emit('config_response', {'status': 'error', 'message': f"Error reprocessing log file: {str(e)}"})
            socketio.emit('alert', {'type': 'System Error', 'message': f"Error reprocessing log file: {str(e)}"})