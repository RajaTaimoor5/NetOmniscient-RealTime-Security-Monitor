import os
import time
import logging
import chardet
from queue import Queue
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from attack_detection import parse_log_line

class LogMonitor:
    """Monitor the firewall log file for changes."""
    def __init__(self, log_path):
        self.log_path = log_path
        self.last_position = 0
        self.last_size = 0
        self.last_check = time.time()
        self.log_queue = Queue()
        self.running = True
        self.last_line_processed = time.time()
        self.last_reprocess = time.time()
        logging.info(f"LogMonitor initialized for {self.log_path}")
        print(f"📜 LogMonitor initialized for {self.log_path}")
        self.read_existing_lines()

    def read_existing_lines(self):
        """Read existing log lines on startup."""
        try:
            if not os.path.exists(self.log_path):
                logging.error(f"Log file {self.log_path} does not exist")
                print(f"❌ Log file {self.log_path} does not exist")
                return
            encoding = self.detect_encoding(self.log_path)
            with open(self.log_path, 'r', encoding=encoding, errors='ignore') as f:
                new_lines = f.readlines()
                logging.debug(f"Read {len(new_lines)} existing lines")
                for line in new_lines:
                    log_entry = parse_log_line(line)
                    if log_entry:
                        entry_time = log_entry['timestamp']
                        if (datetime.now() - entry_time).total_seconds() <= 5 * 3600:
                            self.log_queue.put(log_entry)
                            logging.info(f"Queued recent existing log entry: {log_entry}")
                        else:
                            logging.info(f"Skipped old existing log entry: {entry_time}")
                self.last_position = f.tell()
                self.last_size = os.path.getsize(self.log_path)
                logging.debug(f"Initial last_position: {self.last_position}")
        except PermissionError:
            logging.error(f"Permission denied accessing {self.log_path}")
            print(f"❌ Permission denied accessing {self.log_path}")
        except Exception as e:
            logging.error(f"Error reading log file: {e}")
            print(f"❌ Error reading log file: {e}")

    def start(self):
        """Start monitoring the log file."""
        try:
            logging.info("Starting log monitor observer")
            event_handler = LogHandler(self)
            observer = Observer()
            observer.schedule(event_handler, os.path.dirname(self.log_path), recursive=False)
            observer.start()
            logging.info("Log monitor observer started")
            print("✅ Log monitor observer started")
            while self.running:
                self.fallback_poll()
                current_time = time.time()
                if current_time - self.last_reprocess > 300 and current_time - self.last_line_processed > 60:
                    logging.info("No recent activity, reprocessing log file")
                    self.last_position = 0
                    self.read_existing_lines()
                    self.last_reprocess = current_time
                if current_time - self.last_line_processed > 30:
                    try:
                        last_modified = os.path.getmtime(self.log_path)
                        last_modified_time = datetime.fromtimestamp(last_modified)
                        if (datetime.now() - last_modified_time).total_seconds() > 300:
                            logging.warning("Log file not modified recently")
                            print("⚠️ Log file not modified recently")
                        else:
                            logging.warning("No new log lines in 30s")
                            print("⚠️ No new log lines in 30s")
                    except Exception as e:
                        logging.error(f"Error checking log file modification time: {e}")
                        print(f"❌ Error checking log file modification time: {e}")
                time.sleep(1)
        except Exception as e:
            logging.error(f"Log monitor error: {e}")
            print(f"❌ Log monitor error: {e}")
        finally:
            observer.stop()
            observer.join()
            logging.info("Log monitor stopped")
            print("📜 Log monitor stopped")

    def stop(self):
        """Stop the log monitor."""
        self.running = False
        logging.info("Log monitor stopping")
        print("📜 Log monitor stopping")

    def fallback_poll(self):
        """Poll the log file for changes."""
        try:
            if not os.path.exists(self.log_path):
                logging.error(f"Log file {self.log_path} does not exist")
                print(f"❌ Log file {self.log_path} does not exist")
                return
            current_size = os.path.getsize(self.log_path)
            current_time = time.time()
            if current_size != self.last_size or (current_time - self.last_check > 10):
                logging.info(f"Log file size changed: {self.last_size} -> {current_size}")
                self.read_new_lines()
                self.last_size = current_size
                self.last_check = current_time
        except PermissionError:
            logging.error(f"Permission denied accessing {self.log_path}")
            print(f"❌ Permission denied accessing {self.log_path}")
        except Exception as e:
            logging.error(f"Polling error: {e}")
            print(f"❌ Polling error: {e}")

    def read_new_lines(self):
        """Read new lines from the log file."""
        try:
            encoding = self.detect_encoding(self.log_path)
            with open(self.log_path, 'r', encoding=encoding, errors='ignore') as f:
                f.seek(self.last_position)
                new_lines = f.readlines()
                logging.debug(f"Read {len(new_lines)} new lines at position {self.last_position}")
                for line in new_lines:
                    log_entry = parse_log_line(line)
                    if log_entry:
                        entry_time = log_entry['timestamp']
                        if (datetime.now() - entry_time).total_seconds() <= 5 * 3600:
                            self.log_queue.put(log_entry)
                            logging.info(f"Queued recent new log entry: {log_entry}")
                        else:
                            logging.info(f"Skipped old new log entry: {entry_time}")
                self.last_position = f.tell()
                logging.debug(f"Updated last_position: {self.last_position}")
        except PermissionError:
            logging.error(f"Permission denied accessing {self.log_path}")
            print(f"❌ Permission denied accessing {self.log_path}")
        except Exception as e:
            logging.error(f"Error reading new lines: {e}")
            print(f"❌ Error reading new lines: {e}")

    @staticmethod
    def detect_encoding(file_path):
        """Detect the encoding of a file."""
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read(10000)
                result = chardet.detect(raw_data)
                return result['encoding'] or 'utf-8'
        except Exception as e:
            logging.error(f"Error detecting file encoding: {e}")
            return 'utf-8'

class LogHandler(FileSystemEventHandler):
    """Handle file system events for log file changes."""
    def __init__(self, monitor):
        self.monitor = monitor
        logging.info("LogHandler initialized")

    def on_modified(self, event):
        """Process log file modifications."""
        if event.src_path == self.monitor.log_path:
            logging.info(f"Log file modified: {event.src_path}")
            try:
                self.monitor.read_new_lines()
            except Exception as e:
                logging.error(f"Event handler error: {e}")
                print(f"❌ Event handler error: {e}")
