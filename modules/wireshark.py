"""
AUTARCH Wireshark Module
Packet capture and analysis (scapy + optional tshark)

Live capture, PCAP analysis, protocol/conversation/DNS/HTTP analysis,
credential detection.
"""

import os
import sys
from pathlib import Path

# Module metadata
DESCRIPTION = "Packet capture & analysis (scapy)"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner
from core.wireshark import get_wireshark_manager


class PacketAnalyzer:
    """Packet capture and analysis tools."""

    def __init__(self):
        self.mgr = get_wireshark_manager()

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def show_menu(self):
        while True:
            clear_screen()
            display_banner()
            print(f"\n{Colors.BOLD}Wireshark / Packet Analysis{Colors.RESET}")

            # Status
            status = self.mgr.get_status()
            engine = []
            if status['scapy']:
                engine.append(f'{Colors.GREEN}scapy{Colors.RESET}')
            else:
                engine.append(f'{Colors.RED}scapy (missing){Colors.RESET}')
            if status['tshark']:
                engine.append(f'{Colors.GREEN}tshark{Colors.RESET}')
            else:
                engine.append(f'{Colors.YELLOW}tshark (not found){Colors.RESET}')
            print(f"  Engine: {' + '.join(engine)}")
            if status['can_capture']:
                print(f"  Live capture: {Colors.GREEN}available{Colors.RESET}")
            else:
                print(f"  Live capture: {Colors.YELLOW}needs root{Colors.RESET}")

            print(f"\n  {Colors.CYAN}[1]{Colors.RESET} List Interfaces")
            print(f"  {Colors.CYAN}[2]{Colors.RESET} Start Live Capture")
            print(f"  {Colors.CYAN}[3]{Colors.RESET} Open PCAP File")
            print(f"  {Colors.CYAN}[4]{Colors.RESET} Protocol Analysis")
            print(f"  {Colors.CYAN}[5]{Colors.RESET} Conversation Analysis")
            print(f"  {Colors.CYAN}[6]{Colors.RESET} DNS Query Analysis")
            print(f"  {Colors.CYAN}[7]{Colors.RESET} HTTP Traffic Analysis")
            print(f"  {Colors.CYAN}[8]{Colors.RESET} Credential Detection")
            print(f"  {Colors.CYAN}[9]{Colors.RESET} Export Results")
            print(f"  {Colors.CYAN}[0]{Colors.RESET} Back")

            choice = input(f"\n{Colors.WHITE}Select option: {Colors.RESET}").strip()

            if choice == '0':
                break
            elif choice == '1':
                self.list_interfaces()
            elif choice == '2':
                self.start_capture()
            elif choice == '3':
                self.open_pcap()
            elif choice == '4':
                self.protocol_analysis()
            elif choice == '5':
                self.conversation_analysis()
            elif choice == '6':
                self.dns_analysis()
            elif choice == '7':
                self.http_analysis()
            elif choice == '8':
                self.credential_detection()
            elif choice == '9':
                self.export_results()

    def list_interfaces(self):
        """List network interfaces."""
        print(f"\n{Colors.BOLD}Network Interfaces{Colors.RESET}")
        interfaces = self.mgr.list_interfaces()
        if not interfaces:
            self.print_status("No interfaces found", "error")
        else:
            for i, iface in enumerate(interfaces, 1):
                desc = f" ({iface['description']})" if iface.get('description') else ''
                print(f"  {Colors.CYAN}{i}.{Colors.RESET} {iface['name']}{desc}")
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def start_capture(self):
        """Start a live packet capture."""
        print(f"\n{Colors.BOLD}Live Capture{Colors.RESET}")

        if not self.mgr.can_capture:
            self.print_status("Root privileges required for live capture", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Show interfaces
        interfaces = self.mgr.list_interfaces()
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface['name']}")

        iface_input = input(f"\n{Colors.WHITE}Interface (name or number, Enter for default): {Colors.RESET}").strip()
        interface = None
        if iface_input:
            try:
                idx = int(iface_input) - 1
                if 0 <= idx < len(interfaces):
                    interface = interfaces[idx]['name']
            except ValueError:
                interface = iface_input

        bpf = input(f"{Colors.WHITE}BPF filter (e.g., 'tcp port 80', Enter for all): {Colors.RESET}").strip() or None
        duration_str = input(f"{Colors.WHITE}Duration in seconds (default 30): {Colors.RESET}").strip()
        duration = int(duration_str) if duration_str.isdigit() else 30

        self.print_status(f"Starting capture on {interface or 'default'} for {duration}s...", "info")

        result = self.mgr.start_capture(interface=interface, bpf_filter=bpf, duration=duration)
        if 'error' in result:
            self.print_status(result['error'], "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        self.print_status(f"Capturing... Output: {result.get('file', '')}", "info")

        # Wait for capture to complete
        import time
        try:
            while self.mgr._capture_running:
                stats = self.mgr.get_capture_stats()
                print(f"\r  Packets: {stats.get('packet_count', 0)}", end='', flush=True)
                time.sleep(1)
        except KeyboardInterrupt:
            self.mgr.stop_capture()

        stats = self.mgr.get_capture_stats()
        print()
        self.print_status(f"Capture complete: {stats.get('packet_count', 0)} packets", "success")
        if stats.get('output_file'):
            self.print_status(f"Saved to: {stats['output_file']}", "info")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def open_pcap(self):
        """Open and load a PCAP file."""
        print(f"\n{Colors.BOLD}Open PCAP File{Colors.RESET}")
        filepath = input(f"{Colors.WHITE}PCAP file path: {Colors.RESET}").strip()
        if not filepath:
            return

        self.print_status(f"Loading {filepath}...", "info")
        result = self.mgr.read_pcap(filepath)

        if 'error' in result:
            self.print_status(result['error'], "error")
        else:
            self.print_status(f"Loaded {result['total_packets']} packets from {result['file']}", "success")
            # Show first few packets
            for pkt in result['packets'][:20]:
                print(f"  {pkt.get('src','?'):>15} -> {pkt.get('dst','?'):<15} {pkt.get('protocol',''):>8} {pkt.get('info','')}")
            if result['total_packets'] > 20:
                print(f"  ... and {result['total_packets'] - 20} more packets")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def protocol_analysis(self):
        """Show protocol distribution."""
        print(f"\n{Colors.BOLD}Protocol Analysis{Colors.RESET}")
        result = self.mgr.get_protocol_hierarchy()

        if result['total'] == 0:
            self.print_status("No packets loaded. Open a PCAP or run a capture first.", "warning")
        else:
            print(f"  Total packets: {result['total']}\n")
            for proto, data in result['protocols'].items():
                bar_len = int(data['percent'] / 2)
                bar = '█' * bar_len
                print(f"  {proto:<12} {data['count']:>6}  {data['percent']:>5.1f}%  {Colors.CYAN}{bar}{Colors.RESET}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def conversation_analysis(self):
        """Show IP conversations."""
        print(f"\n{Colors.BOLD}Conversation Analysis{Colors.RESET}")
        convos = self.mgr.extract_conversations()

        if not convos:
            self.print_status("No packets loaded.", "warning")
        else:
            print(f"  {'Source':<20} {'Destination':<20} {'Packets':>8} {'Bytes':>10} {'Protocols'}")
            print(f"  {'─'*20} {'─'*20} {'─'*8} {'─'*10} {'─'*20}")
            for c in convos[:30]:
                protos = ', '.join(c['protocols'][:3])
                print(f"  {c['src']:<20} {c['dst']:<20} {c['packets']:>8} {c['bytes']:>10} {protos}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def dns_analysis(self):
        """Show DNS queries."""
        print(f"\n{Colors.BOLD}DNS Query Analysis{Colors.RESET}")
        queries = self.mgr.extract_dns_queries()

        if not queries:
            self.print_status("No DNS queries found.", "warning")
        else:
            print(f"  {'Query':<40} {'Type':<6} {'Count':>6} {'Response'}")
            print(f"  {'─'*40} {'─'*6} {'─'*6} {'─'*30}")
            for q in queries[:40]:
                resp = q.get('response', '')[:30]
                print(f"  {q['query']:<40} {q['type']:<6} {q['count']:>6} {resp}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def http_analysis(self):
        """Show HTTP requests."""
        print(f"\n{Colors.BOLD}HTTP Traffic Analysis{Colors.RESET}")
        requests = self.mgr.extract_http_requests()

        if not requests:
            self.print_status("No HTTP requests found.", "warning")
        else:
            for r in requests[:30]:
                method = r.get('method', '?')
                host = r.get('host', '')
                path = r.get('path', '')[:60]
                src = r.get('src', '')
                color = Colors.GREEN if method == 'GET' else Colors.YELLOW
                print(f"  {color}{method:<7}{Colors.RESET} {host}{path}  from {src}")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def credential_detection(self):
        """Detect plaintext credentials."""
        print(f"\n{Colors.BOLD}Credential Detection{Colors.RESET}")
        creds = self.mgr.extract_credentials()

        if not creds:
            self.print_status("No plaintext credentials detected.", "info")
        else:
            self.print_status(f"Found {len(creds)} credential artifacts!", "warning")
            for c in creds:
                print(f"  {Colors.RED}[{c['protocol']}]{Colors.RESET} {c['type']}: {c['value']}  ({c['src']} -> {c['dst']})")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def export_results(self):
        """Export packets."""
        print(f"\n{Colors.BOLD}Export Results{Colors.RESET}")
        print(f"  {Colors.CYAN}[1]{Colors.RESET} Export as JSON")
        print(f"  {Colors.CYAN}[2]{Colors.RESET} Export as CSV")

        choice = input(f"\n{Colors.WHITE}Select format: {Colors.RESET}").strip()
        fmt = 'csv' if choice == '2' else 'json'

        result = self.mgr.export_packets(fmt=fmt)
        if 'error' in result:
            self.print_status(result['error'], "error")
        else:
            self.print_status(f"Exported {result['count']} packets to {result['filepath']}", "success")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")


def run():
    """Module entry point."""
    analyzer = PacketAnalyzer()
    analyzer.show_menu()
