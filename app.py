from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
import subprocess
import json
from threading import Thread
import time
import re
from transformers import pipeline

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app, logger=True, engineio_logger=True)  # Enable Socket.IO logging

# Initialize the zero-shot classification pipeline
classifier = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")

class PacketCapture:
    def __init__(self):
        self.capture_process = None
        self.is_capturing = False
        
    def get_wsl_interface(self):
        try:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True)
            print(f"DEBUG: ip route output: {result.stdout}")
            default_route = result.stdout.split('\n')[0]
            interface = re.search(r'dev\s+(\w+)', default_route)
            if interface:
                print(f"DEBUG: Found interface: {interface.group(1)}")
                return interface.group(1)
            else:
                print("DEBUG: No interface found in route, using wlp2s0")
                return "wlp2s0"
        except Exception as e:
            print(f"DEBUG: Error getting interface: {str(e)}")
            return "wlp2s0"
        
    def interpret_request(self, user_request: str) -> dict:
        print(f"DEBUG: Raw user request: '{user_request}'")
        
        # Define possible protocols and their tshark filters
        protocol_filters = {
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "dns": "dns",
            "http": "http",
            "https": "tls",
            "arp": "arp",
            "dhcp": "dhcp"
        }
        
        # Use the model to classify the request
        candidate_labels = list(protocol_filters.keys())
        results = classifier(user_request, candidate_labels)
        print(f"DEBUG: Model classification results: {results}")
        
        # Get the highest confidence protocol
        max_score_index = results['scores'].index(max(results['scores']))
        protocol = results['labels'][max_score_index]
        print(f"DEBUG: Selected protocol: {protocol}")
        
        # Extract IP addresses if present
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, user_request)
        print(f"DEBUG: Found IPs in request: {ips}")
        
        # Build the filter
        filter_parts = [protocol_filters[protocol]]
        if len(ips) >= 2:
            filter_parts.append(f"ip.addr == {ips[0]} and ip.addr == {ips[1]}")
        elif len(ips) == 1:
            filter_parts.append(f"ip.addr == {ips[0]}")
            
        # Extract count if specified
        count_match = re.search(r'(\d+)\s+packets?', user_request.lower())
        count = int(count_match.group(1)) if count_match else 10
            
        config = {
            "filter": " and ".join(filter_parts),
            "count": count,
            "interface": self.get_wsl_interface()
        }
        
        print(f"DEBUG: Final parsed config: {config}")
        return config

    def start_capture(self, user_request: str):
        print("DEBUG: Entering start_capture method")
        if self.is_capturing:
            print("DEBUG: Capture already in progress")
            return False, "Capture already in progress"

        try:
            print("DEBUG: Starting capture process")
            config = self.interpret_request(user_request)
            
            # Build the exact command that works in manual testing
            command = [
                "tshark",
                "-i", config["interface"],
                "-c", str(config["count"]),
                "-T", "json",
                "-f", "icmp6"  # Always capture ICMPv6 packets
            ]
            
            # Print the exact command that will be executed
            print(f"DEBUG: Full tshark command: {' '.join(command)}")
            
            print("DEBUG: Creating subprocess")
            proc = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if proc.returncode != 0:
                print(f"DEBUG: Command failed with error: {proc.stderr}")
                return False, f"Error running tshark: {proc.stderr}"
                
            try:
                packets = json.loads(proc.stdout)
                print(f"DEBUG: Successfully captured {len(packets)} packets")
                
                # Debug: Print the full structure of the first packet
                if packets and len(packets) > 0:
                    sample_packet = packets[0]
                    print(f"DEBUG: Sample packet JSON:")
                    print(json.dumps(sample_packet, indent=2))
                
                # Send each packet to the client
                for packet in packets:
                    socketio.emit('packet', packet)
                    print("DEBUG: Emitted packet to client")
                
                return True, f"Captured {len(packets)} packets"
            except json.JSONDecodeError as e:
                print(f"DEBUG: JSON decode error: {e}")
                return False, f"Error parsing tshark output: {e}"
                
        except Exception as e:
            print(f"DEBUG: Error in start_capture: {str(e)}")
            import traceback
            print(f"DEBUG: Full traceback: {traceback.format_exc()}")
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
    try:
        data = request.json
        user_request = data.get('request', '')
        print(f"DEBUG: Received capture request: {user_request}")
        print(f"DEBUG: Full request data: {data}")
        
        success, message = packet_capture.start_capture(user_request)
        print(f"DEBUG: Capture start result - success: {success}, message: {message}")
        return jsonify({'status': 'success' if success else 'error', 'message': message})
    except Exception as e:
        print(f"DEBUG: Error in start_capture route: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    success, message = packet_capture.stop_capture()
    return jsonify({'status': 'success' if success else 'error', 'message': message})

if __name__ == '__main__':
    socketio.run(app, debug=True) 