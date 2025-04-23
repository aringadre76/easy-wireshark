from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import subprocess
import json
from threading import Thread
import time
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

class PacketCapture:
    def __init__(self):
        self.capture_process = None
        self.is_capturing = False
        
    def get_wsl_interface(self):
        try:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            default_route = result.stdout.split('\n')[0]
            interface = re.search(r'dev\s+(\w+)', default_route)
            return interface.group(1) if interface else "eth0"
        except:
            return "eth0"
        
    def interpret_request(self, user_request: str) -> dict:
        # Simple keyword-based interpretation
        config = {
            "filter": "",
            "count": 10,
            "interface": self.get_wsl_interface()
        }
        
        # Extract IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, user_request)
        
        if len(ips) >= 2:
            config["filter"] = f"ip.addr == {ips[0]} and ip.addr == {ips[1]}"
        elif len(ips) == 1:
            config["filter"] = f"ip.addr == {ips[0]}"
            
        # Add protocol filters
        if "tcp" in user_request.lower():
            config["filter"] += " and tcp" if config["filter"] else "tcp"
        elif "udp" in user_request.lower():
            config["filter"] += " and udp" if config["filter"] else "udp"
        elif "icmp" in user_request.lower():
            config["filter"] += " and icmp" if config["filter"] else "icmp"
        elif "dns" in user_request.lower():
            config["filter"] += " and dns" if config["filter"] else "dns"
            
        # Extract count if specified
        count_match = re.search(r'(\d+)\s+packets?', user_request.lower())
        if count_match:
            config["count"] = int(count_match.group(1))
            
        return config

    def start_capture(self, user_request: str):
        if self.is_capturing:
            return False, "Capture already in progress"

        try:
            config = self.interpret_request(user_request)
            
            command = [
                "tshark",
                "-i", config["interface"],
                "-c", str(config["count"]),
                "-T", "json"
            ]

            if config["filter"]:
                command.extend(["-Y", config["filter"]])

            self.capture_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.is_capturing = True
            return True, f"Started capture with filter: {config['filter']}"
        except Exception as e:
            return False, f"Error starting capture: {str(e)}"

    def stop_capture(self):
        if self.capture_process and self.is_capturing:
            self.capture_process.terminate()
            self.is_capturing = False
            return True, "Capture stopped"
        return False, "No capture in progress"

packet_capture = PacketCapture()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    data = request.json
    user_request = data.get('request', '')
    
    success, message = packet_capture.start_capture(user_request)
    return jsonify({'status': 'success' if success else 'error', 'message': message})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    success, message = packet_capture.stop_capture()
    return jsonify({'status': 'success' if success else 'error', 'message': message})

def capture_thread():
    while True:
        if packet_capture.is_capturing and packet_capture.capture_process:
            line = packet_capture.capture_process.stdout.readline()
            if line:
                try:
                    packet = json.loads(line)
                    socketio.emit('packet', packet)
                except json.JSONDecodeError:
                    continue
            else:
                packet_capture.is_capturing = False
        time.sleep(0.1)

if __name__ == '__main__':
    capture_thread = Thread(target=capture_thread)
    capture_thread.daemon = True
    capture_thread.start()
    socketio.run(app, debug=True) 