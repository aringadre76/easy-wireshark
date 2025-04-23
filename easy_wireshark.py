import os
import sys
import json
import subprocess
from typing import List, Dict, Any
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

console = Console()

class ProtocolAnalyzer:
    def __init__(self):
        self.protocol_info = {
            "TCP": {
                "description": "Transmission Control Protocol - Reliable, connection-oriented protocol",
                "common_ports": {
                    "80": "HTTP - Web traffic",
                    "443": "HTTPS - Secure web traffic",
                    "22": "SSH - Secure shell",
                    "25": "SMTP - Email sending",
                    "53": "DNS - Domain name resolution"
                }
            },
            "UDP": {
                "description": "User Datagram Protocol - Fast, connectionless protocol",
                "common_ports": {
                    "53": "DNS - Domain name resolution",
                    "67": "DHCP - Dynamic IP assignment",
                    "123": "NTP - Network time protocol",
                    "161": "SNMP - Network management"
                }
            },
            "ICMP": {
                "description": "Internet Control Message Protocol - Network diagnostic and error reporting",
                "types": {
                    "0": "Echo Reply",
                    "8": "Echo Request",
                    "3": "Destination Unreachable",
                    "11": "Time Exceeded"
                }
            },
            "DNS": {
                "description": "Domain Name System - Converts domain names to IP addresses",
                "query_types": {
                    "1": "A - IPv4 address",
                    "28": "AAAA - IPv6 address",
                    "2": "NS - Name server",
                    "5": "CNAME - Canonical name"
                }
            }
        }

    def analyze_packet(self, packet: Dict[str, Any]) -> str:
        try:
            layers = packet.get("_source", {}).get("layers", {})
            frame = layers.get("frame", {})
            protocols = frame.get("frame.protocols", "").split(":")
            
            analysis = []
            
            for protocol in protocols:
                if protocol in self.protocol_info:
                    info = self.protocol_info[protocol]
                    analysis.append(f"Protocol: {protocol}")
                    analysis.append(f"Description: {info['description']}")
                    
                    if protocol == "TCP" or protocol == "UDP":
                        src_port = layers.get(protocol.lower(), {}).get(f"{protocol.lower()}.srcport", "")
                        dst_port = layers.get(protocol.lower(), {}).get(f"{protocol.lower()}.dstport", "")
                        
                        if src_port in info["common_ports"]:
                            analysis.append(f"Source Port {src_port}: {info['common_ports'][src_port]}")
                        if dst_port in info["common_ports"]:
                            analysis.append(f"Destination Port {dst_port}: {info['common_ports'][dst_port]}")
                    
                    elif protocol == "ICMP":
                        icmp_type = layers.get("icmp", {}).get("icmp.type", "")
                        if icmp_type in info["types"]:
                            analysis.append(f"ICMP Type {icmp_type}: {info['types'][icmp_type]}")
                    
                    elif protocol == "DNS":
                        query_type = layers.get("dns", {}).get("dns.qry.type", "")
                        if query_type in info["query_types"]:
                            analysis.append(f"DNS Query Type {query_type}: {info['query_types'][query_type]}")
            
            if not analysis:
                analysis.append("No detailed protocol information available")
            
            return "\n".join(analysis)
        except Exception as e:
            return f"Error analyzing packet: {str(e)}"

class EasyWireshark:
    def __init__(self):
        self.console = Console()
        self.analyzer = ProtocolAnalyzer()
        
    def get_user_filters(self) -> str:
        self.console.print("\n[bold cyan]Enter your capture filters:[/bold cyan]")
        self.console.print("[yellow]Example:[/yellow] ip.addr == 192.168.1.1 and tcp.port == 80")
        self.console.print("[yellow]Leave empty for no filters[/yellow]")
        
        ip1 = Prompt.ask("First IP address (optional)")
        ip2 = Prompt.ask("Second IP address (optional)")
        protocol = Prompt.ask("Protocol (optional, e.g., tcp, udp, icmp)")
        
        filters = []
        if ip1:
            filters.append(f"ip.addr == {ip1}")
        if ip2:
            filters.append(f"ip.addr == {ip2}")
        if protocol:
            filters.append(protocol)
            
        return " and ".join(filters) if filters else ""
        
    def capture_traffic(self, interface: str = None, count: int = 10, display_filter: str = "") -> List[Dict[str, Any]]:
        if interface is None:
            interface = self._get_default_interface()
            
        command = [
            "tshark",
            "-i", interface,
            "-c", str(count),
            "-T", "json"
        ]
        
        if display_filter:
            command.extend(["-Y", display_filter])
        
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode != 0:
                raise Exception(f"Tshark error: {result.stderr}")
                
            packets = json.loads(result.stdout)
            return packets
        except Exception as e:
            self.console.print(f"[red]Error capturing traffic: {str(e)}[/red]")
            return []

    def _get_default_interface(self) -> str:
        try:
            result = subprocess.run(["tshark", "-D"], capture_output=True, text=True)
            interfaces = result.stdout.strip().split('\n')
            return interfaces[0].split('.')[1].strip()
        except Exception as e:
            self.console.print(f"[red]Error getting default interface: {str(e)}[/red]")
            return "eth0"

    def display_packet(self, packet: Dict[str, Any], analysis: str):
        table = Table(title="Packet Information")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        packet_info = {
            "Timestamp": packet.get("_source", {}).get("layers", {}).get("frame", {}).get("frame.time", ""),
            "Protocol": packet.get("_source", {}).get("layers", {}).get("frame", {}).get("frame.protocols", ""),
            "Source": packet.get("_source", {}).get("layers", {}).get("ip", {}).get("ip.src", ""),
            "Destination": packet.get("_source", {}).get("layers", {}).get("ip", {}).get("ip.dst", ""),
        }
        
        for field, value in packet_info.items():
            table.add_row(field, value)
        
        self.console.print(table)
        self.console.print(Panel(analysis, title="Analysis", border_style="blue"))

def main():
    try:
        easy_wireshark = EasyWireshark()
        console.print("[bold green]Starting Easy Wireshark...[/bold green]")
        
        while True:
            display_filter = easy_wireshark.get_user_filters()
            count = Prompt.ask("Number of packets to capture", default="10")
            
            console.print(f"\n[yellow]Capturing traffic with filter: {display_filter if display_filter else 'none'}[/yellow]")
            
            packets = easy_wireshark.capture_traffic(count=int(count), display_filter=display_filter)
            
            if not packets:
                console.print("[red]No packets captured with the given filter[/red]")
            else:
                for packet in packets:
                    analysis = easy_wireshark.analyzer.analyze_packet(packet)
                    easy_wireshark.display_packet(packet, analysis)
                    console.print("\n" + "="*80 + "\n")
            
            if Prompt.ask("\nCapture more packets?", choices=["y", "n"], default="y") == "n":
                break
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping capture...[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

if __name__ == "__main__":
    main() 