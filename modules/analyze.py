"""
AUTARCH Analyze Module
Forensics and analysis tools

File analysis, hash generation, string extraction, and more.
"""

import os
import sys
import subprocess
import hashlib
import re
try:
    import magic
except ImportError:
    magic = None
from pathlib import Path
from datetime import datetime

# Module metadata
DESCRIPTION = "Forensics & file analysis tools"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "analyze"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner


class Analyzer:
    """Forensics and analysis tools."""

    def __init__(self):
        pass

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def run_cmd(self, cmd: str) -> tuple:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
            return result.returncode == 0, result.stdout.strip()
        except:
            return False, ""

    def get_file_hashes(self, filepath: str) -> dict:
        """Calculate various hashes for a file."""
        p = Path(filepath)
        if not p.exists() or not p.is_file():
            return {}

        hashes = {}
        with open(p, 'rb') as f:
            content = f.read()
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()

        return hashes

    def analyze_file(self):
        """Comprehensive file analysis."""
        print(f"\n{Colors.BOLD}File Analysis{Colors.RESET}")
        filepath = input(f"{Colors.WHITE}Enter file path: {Colors.RESET}").strip()

        if not filepath:
            return

        p = Path(filepath).expanduser()
        if not p.exists():
            self.print_status(f"File not found: {filepath}", "error")
            return

        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}File: {p.name}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Basic info
        stat = p.stat()
        print(f"{Colors.CYAN}Basic Info:{Colors.RESET}")
        print(f"  Path:     {p.absolute()}")
        print(f"  Size:     {stat.st_size:,} bytes")
        print(f"  Modified: {datetime.fromtimestamp(stat.st_mtime)}")
        print(f"  Created:  {datetime.fromtimestamp(stat.st_ctime)}")
        print(f"  Mode:     {oct(stat.st_mode)}")

        # File type
        print(f"\n{Colors.CYAN}File Type:{Colors.RESET}")
        try:
            file_magic = magic.Magic(mime=True)
            mime_type = file_magic.from_file(str(p))
            print(f"  MIME:     {mime_type}")

            file_magic = magic.Magic()
            file_desc = file_magic.from_file(str(p))
            print(f"  Type:     {file_desc}")
        except:
            success, output = self.run_cmd(f"file '{p}'")
            if success:
                print(f"  Type:     {output.split(':', 1)[-1].strip()}")

        # Hashes
        print(f"\n{Colors.CYAN}Hashes:{Colors.RESET}")
        hashes = self.get_file_hashes(str(p))
        for algo, value in hashes.items():
            print(f"  {algo.upper():8} {value}")

        # Check if executable
        if p.suffix in ['.exe', '.dll', '.so', '.elf', ''] or stat.st_mode & 0o111:
            self.analyze_executable(str(p))

    def analyze_executable(self, filepath: str):
        """Additional analysis for executables."""
        print(f"\n{Colors.CYAN}Executable Analysis:{Colors.RESET}")

        # Strings
        success, output = self.run_cmd(f"strings '{filepath}' 2>/dev/null | head -50")
        if success and output:
            # Look for interesting strings
            interesting = []
            patterns = [
                r'https?://[^\s]+',  # URLs
                r'\d+\.\d+\.\d+\.\d+',  # IPs
                r'password|passwd|secret|key|token',  # Credentials
                r'/bin/sh|/bin/bash|cmd\.exe',  # Shells
            ]
            for line in output.split('\n'):
                for pattern in patterns:
                    if re.search(pattern, line, re.I):
                        interesting.append(line.strip())
                        break

            if interesting:
                print(f"  {Colors.YELLOW}Interesting strings found:{Colors.RESET}")
                for s in interesting[:10]:
                    print(f"    {s[:80]}")

        # Check for packing
        success, output = self.run_cmd(f"readelf -h '{filepath}' 2>/dev/null")
        if success:
            if 'Entry point' in output:
                print(f"  ELF executable detected")

    def extract_strings(self):
        """Extract strings from file."""
        print(f"\n{Colors.BOLD}String Extraction{Colors.RESET}")
        filepath = input(f"{Colors.WHITE}Enter file path: {Colors.RESET}").strip()

        if not filepath:
            return

        p = Path(filepath).expanduser()
        if not p.exists():
            self.print_status(f"File not found", "error")
            return

        min_len = input(f"{Colors.WHITE}Minimum string length [4]: {Colors.RESET}").strip() or "4"

        print(f"\n{Colors.CYAN}Extracting strings...{Colors.RESET}\n")

        success, output = self.run_cmd(f"strings -n {min_len} '{p}' 2>/dev/null")
        if success:
            lines = output.split('\n')
            print(f"Found {len(lines)} strings\n")

            # Categorize
            urls = [l for l in lines if re.search(r'https?://', l)]
            ips = [l for l in lines if re.search(r'\b\d+\.\d+\.\d+\.\d+\b', l)]
            paths = [l for l in lines if re.search(r'^/[a-z]', l, re.I)]
            emails = [l for l in lines if re.search(r'[\w.-]+@[\w.-]+', l)]

            if urls:
                print(f"{Colors.CYAN}URLs ({len(urls)}):{Colors.RESET}")
                for u in urls[:10]:
                    print(f"  {u}")

            if ips:
                print(f"\n{Colors.CYAN}IP Addresses ({len(ips)}):{Colors.RESET}")
                for ip in ips[:10]:
                    print(f"  {ip}")

            if emails:
                print(f"\n{Colors.CYAN}Emails ({len(emails)}):{Colors.RESET}")
                for e in emails[:10]:
                    print(f"  {e}")

            if paths:
                print(f"\n{Colors.CYAN}Paths ({len(paths)}):{Colors.RESET}")
                for p in paths[:10]:
                    print(f"  {p}")

            # Save option
            save = input(f"\n{Colors.WHITE}Save all strings to file? (y/n): {Colors.RESET}").strip().lower()
            if save == 'y':
                outfile = f"{p.stem}_strings.txt"
                with open(outfile, 'w') as f:
                    f.write(output)
                self.print_status(f"Saved to {outfile}", "success")

    def hash_lookup(self):
        """Look up hash in threat intel."""
        print(f"\n{Colors.BOLD}Hash Lookup{Colors.RESET}")
        hash_input = input(f"{Colors.WHITE}Enter hash (MD5/SHA1/SHA256): {Colors.RESET}").strip()

        if not hash_input:
            return

        # Determine hash type
        hash_len = len(hash_input)
        if hash_len == 32:
            hash_type = "MD5"
        elif hash_len == 40:
            hash_type = "SHA1"
        elif hash_len == 64:
            hash_type = "SHA256"
        else:
            self.print_status("Invalid hash length", "error")
            return

        print(f"\n{Colors.CYAN}Hash Type: {hash_type}{Colors.RESET}")
        print(f"{Colors.CYAN}Hash:      {hash_input}{Colors.RESET}\n")

        # VirusTotal URL
        print(f"{Colors.DIM}VirusTotal: https://www.virustotal.com/gui/file/{hash_input}{Colors.RESET}")
        print(f"{Colors.DIM}Hybrid Analysis: https://www.hybrid-analysis.com/search?query={hash_input}{Colors.RESET}")

    def analyze_log(self):
        """Analyze log files for anomalies."""
        print(f"\n{Colors.BOLD}Log Analysis{Colors.RESET}")
        print(f"{Colors.DIM}Common logs: /var/log/auth.log, /var/log/syslog, /var/log/apache2/access.log{Colors.RESET}\n")

        filepath = input(f"{Colors.WHITE}Enter log file path: {Colors.RESET}").strip()
        if not filepath:
            return

        p = Path(filepath).expanduser()
        if not p.exists():
            self.print_status(f"File not found", "error")
            return

        print(f"\n{Colors.CYAN}Analyzing {p.name}...{Colors.RESET}\n")

        # Read log
        try:
            with open(p, 'r', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            self.print_status(f"Error reading file: {e}", "error")
            return

        print(f"Total lines: {len(lines)}")

        # Extract IPs
        all_ips = []
        for line in lines:
            ips = re.findall(r'\b(\d+\.\d+\.\d+\.\d+)\b', line)
            all_ips.extend(ips)

        if all_ips:
            from collections import Counter
            ip_counts = Counter(all_ips)
            print(f"\n{Colors.CYAN}Top IP Addresses:{Colors.RESET}")
            for ip, count in ip_counts.most_common(10):
                print(f"  {ip:20} {count:>6} occurrences")

        # Look for error patterns
        errors = [l for l in lines if re.search(r'error|fail|denied|invalid', l, re.I)]
        if errors:
            print(f"\n{Colors.YELLOW}Error/Failure entries: {len(errors)}{Colors.RESET}")
            print(f"{Colors.DIM}Recent errors:{Colors.RESET}")
            for e in errors[-5:]:
                print(f"  {e.strip()[:100]}")

        # Timestamps
        timestamps = []
        for line in lines:
            match = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', line)
            if match:
                timestamps.append(match.group(1))

        if timestamps:
            print(f"\n{Colors.CYAN}Time Range:{Colors.RESET}")
            print(f"  First: {timestamps[0]}")
            print(f"  Last:  {timestamps[-1]}")

    def hex_dump(self):
        """Create hex dump of file."""
        print(f"\n{Colors.BOLD}Hex Dump{Colors.RESET}")
        filepath = input(f"{Colors.WHITE}Enter file path: {Colors.RESET}").strip()

        if not filepath:
            return

        p = Path(filepath).expanduser()
        if not p.exists():
            self.print_status(f"File not found", "error")
            return

        offset = input(f"{Colors.WHITE}Start offset [0]: {Colors.RESET}").strip() or "0"
        length = input(f"{Colors.WHITE}Length [256]: {Colors.RESET}").strip() or "256"

        try:
            offset = int(offset, 0)  # Support hex input
            length = int(length, 0)
        except:
            self.print_status("Invalid offset/length", "error")
            return

        print(f"\n{Colors.CYAN}Hex dump of {p.name} (offset={hex(offset)}, length={length}):{Colors.RESET}\n")

        with open(p, 'rb') as f:
            f.seek(offset)
            data = f.read(length)

        # Format hex dump
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"  {offset+i:08x}  {hex_part:<48}  {ascii_part}")

    def compare_files(self):
        """Compare two files."""
        print(f"\n{Colors.BOLD}File Comparison{Colors.RESET}")

        file1 = input(f"{Colors.WHITE}First file: {Colors.RESET}").strip()
        file2 = input(f"{Colors.WHITE}Second file: {Colors.RESET}").strip()

        if not file1 or not file2:
            return

        p1 = Path(file1).expanduser()
        p2 = Path(file2).expanduser()

        if not p1.exists() or not p2.exists():
            self.print_status("One or both files not found", "error")
            return

        print(f"\n{Colors.CYAN}Comparing files...{Colors.RESET}\n")

        # Size comparison
        s1, s2 = p1.stat().st_size, p2.stat().st_size
        print(f"File 1 size: {s1:,} bytes")
        print(f"File 2 size: {s2:,} bytes")
        print(f"Difference:  {abs(s1-s2):,} bytes")

        # Hash comparison
        h1 = self.get_file_hashes(str(p1))
        h2 = self.get_file_hashes(str(p2))

        print(f"\n{Colors.CYAN}Hash Comparison:{Colors.RESET}")
        for algo in ['md5', 'sha256']:
            match = h1.get(algo) == h2.get(algo)
            status = f"{Colors.GREEN}MATCH{Colors.RESET}" if match else f"{Colors.RED}DIFFERENT{Colors.RESET}"
            print(f"  {algo.upper()}: {status}")

        if h1.get('sha256') != h2.get('sha256'):
            # Show diff if text files
            success, output = self.run_cmd(f"diff '{p1}' '{p2}' 2>/dev/null | head -30")
            if success and output:
                print(f"\n{Colors.CYAN}Differences (first 30 lines):{Colors.RESET}")
                print(output)

    def show_menu(self):
        clear_screen()
        display_banner()

        print(f"{Colors.CYAN}{Colors.BOLD}  Analysis & Forensics{Colors.RESET}")
        print(f"{Colors.DIM}  File analysis and forensics tools{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()
        print(f"  {Colors.CYAN}[1]{Colors.RESET} Analyze File")
        print(f"  {Colors.CYAN}[2]{Colors.RESET} Extract Strings")
        print(f"  {Colors.CYAN}[3]{Colors.RESET} Hash Lookup")
        print(f"  {Colors.CYAN}[4]{Colors.RESET} Analyze Log")
        print(f"  {Colors.CYAN}[5]{Colors.RESET} Hex Dump")
        print(f"  {Colors.CYAN}[6]{Colors.RESET} Compare Files")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

    def run(self):
        while True:
            self.show_menu()
            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0":
                    break
                elif choice == "1":
                    self.analyze_file()
                elif choice == "2":
                    self.extract_strings()
                elif choice == "3":
                    self.hash_lookup()
                elif choice == "4":
                    self.analyze_log()
                elif choice == "5":
                    self.hex_dump()
                elif choice == "6":
                    self.compare_files()

                if choice in ["1", "2", "3", "4", "5", "6"]:
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break


def run():
    Analyzer().run()


if __name__ == "__main__":
    run()
