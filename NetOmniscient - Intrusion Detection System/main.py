import os
import logging
import threading
from flask import Flask
from flask_socketio import SocketIO
from firewall_monitor import LogMonitor
from packet_sniffing import start_sniffing, stop_sniffing, get_active_interface
from background_tasks import background_task
from gui import setup_gui

# Set up application logging
LOG_FILE = 'netomniscient.log'
LOG_DIR = os.path.join(os.path.expanduser('~'), 'NetOmniscient_Logs')
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, LOG_FILE)
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s'
)

# Flask and SocketIO setup
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

# Configuration
FIREWALL_LOG_PATH = r'C:\Windows\System32\LogFiles\Firewall\pfirewall.log'
recent_logs = []

if __name__ == '__main__':
    try:
        # Initialize log monitor
        monitor = LogMonitor(FIREWALL_LOG_PATH)
        observer_thread = threading.Thread(target=monitor.start)
        observer_thread.daemon = True
        observer_thread.start()

        # Select network interface dynamically
        wifi_interface = get_active_interface()
        if not wifi_interface:
            logging.error("No active network interface found")
            print("❌ No active network interface found")
            exit(1)
        logging.info(f"Attempting to start sniffing on {wifi_interface}")
        print(f"📡 Attempting to start sniffing on {wifi_interface}")
        start_sniffing(wifi_interface)

        # Setup GUI
        setup_gui(app, socketio, monitor, recent_logs)

        # Start background task
        socketio.start_background_task(background_task, monitor, socketio, recent_logs)

        # Run Flask app
        socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    except KeyboardInterrupt:
        logging.info("Application shutting down")
        print("✅ Application shutting down")
        monitor.stop()
        stop_sniffing()
    except Exception as e:
        logging.error(f"Startup error: {e}")
        print(f"❌ Startup error: {e}")
        exit(1)