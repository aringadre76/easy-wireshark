# Easy Wireshark

An LLM-powered network traffic analyzer that uses Wireshark's tshark command-line tool to capture and analyze network traffic in a user-friendly way.

## Prerequisites

- Python 3.8+
- Wireshark (tshark) installed
- Local LLM model (GPT-2)

## Installation

1. Install Wireshark (tshark) on your system:
   ```bash
   sudo apt-get update
   sudo apt-get install wireshark
   sudo usermod -a -G wireshark $USER
   ```
   (Log out and back in after adding to wireshark group)

2. Clone this repository

3. Install Python dependencies:
   ```bash
   pip3 install -r requirements.txt
   ```

## Usage

Run the analyzer:
```bash
python3 app.py
```

Then open your browser to:
```
http://localhost:5000
```

## Features

- Natural language packet capture requests
- Real-time network traffic capture
- Local LLM-powered command interpretation
- User-friendly explanations of network protocols
- Rich terminal output formatting

## Example Queries

- "Show me all TCP packets between 192.168.1.1 and 8.8.8.8"
- "Capture DNS traffic from my computer"
- "Show me all HTTP traffic on port 80"