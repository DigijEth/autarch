"""
AUTARCH Workflow Module
Automated pentest pipeline orchestration

Run multi-step security assessments with automated data flow between tools.
"""

import os
import sys
import json
import subprocess
import re
import time
from pathlib import Path
from datetime import datetime

# Module metadata
DESCRIPTION = "Automated pentest workflow"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner


class WorkflowRunner:
    """Orchestrate multi-step pentest workflows."""

    def __init__(self):
        self.results_dir = Path("results")
        self.results_dir.mkdir(exist_ok=True)

    def print_status(self, msg, level="info"):
        icons = {"info": f"{Colors.CYAN}[*]", "success": f"{Colors.GREEN}[+]",
                 "warning": f"{Colors.YELLOW}[!]", "error": f"{Colors.RED}[-]"}
        icon = icons.get(level, icons["info"])
        print(f"  {icon} {msg}{Colors.RESET}")

    # =========================================================================
    # MENU
    # =========================================================================

    def show_menu(self):
        clear_screen()
        display_banner()

        print(f"{Colors.RED}{Colors.BOLD}  Automated Workflow{Colors.RESET}")
        print(f"{Colors.DIM}  Multi-step pentest pipeline orchestration{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()
        print(f"  {Colors.RED}[1]{Colors.RESET} New Workflow     {Colors.DIM}- Full automated pipeline{Colors.RESET}")
        print(f"  {Colors.RED}[2]{Colors.RESET} Quick Scan       {Colors.DIM}- Nmap → CVE → Report (no LLM){Colors.RESET}")
        print(f"  {Colors.RED}[3]{Colors.RESET} Resume Workflow  {Colors.DIM}- Load saved state{Colors.RESET}")
        print()
        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

    # =========================================================================
    # NMAP SCAN (shared helper)
    # =========================================================================

    def _nmap_service_scan(self, target):
        """Run nmap service detection scan on target."""
        self.print_status(f"Running nmap -sV -T4 on {target}...", "info")
        try:
            result = subprocess.run(
                f"nmap -sV --top-ports 20 -T4 {target}",
                shell=True, capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                self.print_status("nmap scan failed", "error")
                return []

            services = []
            port_re = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)')
            for line in result.stdout.split('\n'):
                m = port_re.match(line.strip())
                if m:
                    parts = m.group(4).strip().split()
                    services.append({
                        'port': int(m.group(1)),
                        'protocol': m.group(2),
                        'service': parts[0] if parts else m.group(3),
                        'version': ' '.join(parts[1:]) if len(parts) > 1 else ''
                    })

            self.print_status(f"Found {len(services)} open services", "success")
            return services

        except subprocess.TimeoutExpired:
            self.print_status("nmap timed out after 5 minutes", "error")
            return []
        except Exception as e:
            self.print_status(f"Scan error: {e}", "error")
            return []

    # =========================================================================
    # CVE CORRELATION (shared helper)
    # =========================================================================

    def _correlate_cves(self, services):
        """Correlate services with CVEs from the database."""
        try:
            from core.cve import get_cve_db
            cve_db = get_cve_db()
        except Exception as e:
            self.print_status(f"CVE database unavailable: {e}", "warning")
            return []

        SERVICE_TO_CPE = {
            'apache': ('apache', 'http_server'), 'nginx': ('f5', 'nginx'),
            'openssh': ('openbsd', 'openssh'), 'ssh': ('openbsd', 'openssh'),
            'mysql': ('oracle', 'mysql'), 'postgresql': ('postgresql', 'postgresql'),
            'samba': ('samba', 'samba'), 'smb': ('samba', 'samba'),
            'vsftpd': ('vsftpd_project', 'vsftpd'), 'proftpd': ('proftpd', 'proftpd'),
            'postfix': ('postfix', 'postfix'), 'dovecot': ('dovecot', 'dovecot'),
            'php': ('php', 'php'), 'tomcat': ('apache', 'tomcat'),
            'isc': ('isc', 'bind'), 'bind': ('isc', 'bind'),
        }

        correlations = []
        for svc in services:
            self.print_status(f"Checking CVEs for {svc['service']}:{svc.get('version', '?')} on port {svc['port']}...", "info")

            cves = []
            svc_lower = svc['service'].lower()
            version = svc.get('version', '').split()[0] if svc.get('version') else ''

            if svc_lower in SERVICE_TO_CPE and version:
                vendor, product = SERVICE_TO_CPE[svc_lower]
                cpe = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                try:
                    cves = cve_db.search_cves(cpe_pattern=cpe)
                except Exception:
                    pass

            if not cves and version:
                try:
                    cves = cve_db.search_cves(keyword=f"{svc['service']} {version}")
                except Exception:
                    pass

            if cves:
                self.print_status(f"  Found {len(cves)} CVEs", "success")
            else:
                self.print_status(f"  No CVEs found", "info")

            correlations.append({
                'service': svc,
                'cves': cves[:20]  # cap per service
            })

        return correlations

    # =========================================================================
    # FULL WORKFLOW
    # =========================================================================

    def run_workflow(self, target):
        """Run full automated pentest workflow."""
        clear_screen()
        display_banner()
        print(f"{Colors.RED}{Colors.BOLD}  Full Workflow - {target}{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        state = {
            'target': target,
            'started': datetime.now().isoformat(),
            'services': [],
            'correlations': [],
            'exploits': [],
            'report': None,
            'current_step': 1
        }
        state_file = self.results_dir / f"workflow_{target.replace('.', '-').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        # Step 1: Nmap scan
        print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 1/4: Service Detection{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}")
        services = self._nmap_service_scan(target)
        state['services'] = services
        state['current_step'] = 2
        self._save_state(state, state_file)

        if not services:
            self.print_status("No services found. Workflow cannot continue.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        cont = input(f"\n{Colors.WHITE}  Continue to CVE correlation? [Y/n]: {Colors.RESET}").strip().lower()
        if cont == 'n':
            self.print_status(f"State saved to {state_file}", "info")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Step 2: CVE correlation
        print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 2/4: CVE Correlation{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}")
        correlations = self._correlate_cves(services)
        state['correlations'] = correlations
        state['current_step'] = 3
        self._save_state(state, state_file)

        total_cves = sum(len(c.get('cves', [])) for c in correlations)
        self.print_status(f"Total CVEs found: {total_cves}", "success" if total_cves > 0 else "info")

        cont = input(f"\n{Colors.WHITE}  Continue to exploit suggestion? [Y/n]: {Colors.RESET}").strip().lower()
        if cont == 'n':
            # Skip to report
            self._generate_workflow_report(state)
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Step 3: Exploit suggestion (LLM)
        print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 3/4: Exploit Suggestion{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}")
        exploits = self._suggest_exploits(services, correlations)
        state['exploits'] = exploits
        state['current_step'] = 4
        self._save_state(state, state_file)

        cont = input(f"\n{Colors.WHITE}  Generate report? [Y/n]: {Colors.RESET}").strip().lower()
        if cont == 'n':
            self.print_status(f"State saved to {state_file}", "info")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Step 4: Report
        print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 4/4: Report Generation{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}")
        self._generate_workflow_report(state)
        state['current_step'] = 5
        self._save_state(state, state_file)

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # QUICK SCAN
    # =========================================================================

    def quick_scan(self, target):
        """Run quick scan: Nmap → CVE → Report (no LLM)."""
        clear_screen()
        display_banner()
        print(f"{Colors.RED}{Colors.BOLD}  Quick Scan - {target}{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        start_time = time.time()

        # Step 1: Nmap
        print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 1/3: Service Detection{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}")
        services = self._nmap_service_scan(target)
        if not services:
            self.print_status("No services found.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Step 2: CVE correlation
        print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 2/3: CVE Correlation{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}")
        correlations = self._correlate_cves(services)

        total_cves = sum(len(c.get('cves', [])) for c in correlations)
        self.print_status(f"Total CVEs found: {total_cves}", "success" if total_cves > 0 else "info")

        # Step 3: Report
        print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 3/3: Report Generation{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 40}{Colors.RESET}")

        scan_time = time.time() - start_time
        state = {
            'target': target,
            'services': services,
            'correlations': correlations,
            'exploits': [],
            'scan_time': scan_time
        }
        self._generate_workflow_report(state)

        self.print_status(f"Quick scan completed in {scan_time:.1f}s", "success")
        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # RESUME WORKFLOW
    # =========================================================================

    def resume_workflow(self):
        """Resume a saved workflow from JSON state."""
        clear_screen()
        display_banner()
        print(f"{Colors.RED}{Colors.BOLD}  Resume Workflow{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        state_files = sorted(self.results_dir.glob("workflow_*.json"))
        if not state_files:
            self.print_status("No saved workflows found.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        for i, f in enumerate(state_files, 1):
            try:
                with open(f, 'r') as fh:
                    data = json.load(fh)
                target = data.get('target', '?')
                step = data.get('current_step', '?')
                started = data.get('started', '?')
                print(f"  {Colors.RED}[{i}]{Colors.RESET} {f.name}")
                print(f"      {Colors.DIM}Target: {target} | Step: {step}/4 | Started: {started}{Colors.RESET}")
            except Exception:
                print(f"  {Colors.RED}[{i}]{Colors.RESET} {f.name} {Colors.DIM}(corrupt){Colors.RESET}")
        print(f"\n  {Colors.DIM}[0]{Colors.RESET} Back")

        sel = input(f"\n{Colors.WHITE}  Select: {Colors.RESET}").strip()
        if sel == "0":
            return

        try:
            idx = int(sel) - 1
            with open(state_files[idx], 'r') as f:
                state = json.load(f)
        except (ValueError, IndexError, json.JSONDecodeError) as e:
            self.print_status(f"Error: {e}", "error")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        target = state.get('target', '')
        current_step = state.get('current_step', 1)
        state_file = state_files[idx]

        self.print_status(f"Resuming workflow for {target} at step {current_step}/4", "info")

        if current_step <= 1:
            services = self._nmap_service_scan(target)
            state['services'] = services
            state['current_step'] = 2
            self._save_state(state, state_file)
        else:
            services = state.get('services', [])

        if not services:
            self.print_status("No services available.", "warning")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        if current_step <= 2:
            print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 2/4: CVE Correlation{Colors.RESET}")
            correlations = self._correlate_cves(services)
            state['correlations'] = correlations
            state['current_step'] = 3
            self._save_state(state, state_file)
        else:
            correlations = state.get('correlations', [])

        if current_step <= 3:
            cont = input(f"\n{Colors.WHITE}  Run exploit suggestion? [Y/n]: {Colors.RESET}").strip().lower()
            if cont != 'n':
                print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 3/4: Exploit Suggestion{Colors.RESET}")
                exploits = self._suggest_exploits(services, correlations)
                state['exploits'] = exploits
            state['current_step'] = 4
            self._save_state(state, state_file)

        if current_step <= 4:
            print(f"\n{Colors.CYAN}{Colors.BOLD}  Step 4/4: Report Generation{Colors.RESET}")
            self._generate_workflow_report(state)
            state['current_step'] = 5
            self._save_state(state, state_file)

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _suggest_exploits(self, services, correlations):
        """Try LLM-based exploit suggestion, fallback to CVE-MSF lookup."""
        exploits = []

        # Collect all CVEs
        all_cves = []
        for corr in correlations:
            for cve in corr.get('cves', []):
                all_cves.append(cve)

        if not all_cves:
            self.print_status("No CVEs to suggest exploits for.", "info")
            return []

        # Try LLM
        try:
            from core.llm import get_llm
            llm = get_llm()
            if llm and llm.is_loaded():
                self.print_status("Using LLM for exploit suggestions...", "info")

                svc_text = "\n".join(
                    f"- {s['service']}:{s.get('version', '?')} on port {s['port']}"
                    for s in services
                )
                cve_text = "\n".join(
                    f"- {c.get('id', '?')} (CVSS {c.get('cvss', '?')}): {c.get('description', '')[:100]}"
                    for c in all_cves[:20]
                )

                prompt = f"""Given these services and vulnerabilities, suggest the top 5 attack paths.

Services:
{svc_text}

CVEs:
{cve_text}

For each suggestion provide: rank, Metasploit module path (if known), target service, CVE, and reasoning.
Format each as: N. MODULE | TARGET | CVE | REASONING"""

                response = llm.generate(prompt)
                if response:
                    # Parse suggestions
                    for line in response.split('\n'):
                        line = line.strip()
                        match = re.match(r'\d+\.\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+)', line)
                        if match:
                            exploits.append({
                                'module': match.group(1).strip(),
                                'target': match.group(2).strip(),
                                'cve': match.group(3).strip(),
                                'reasoning': match.group(4).strip()
                            })

                    if exploits:
                        self.print_status(f"LLM suggested {len(exploits)} attack paths", "success")
                        for i, exp in enumerate(exploits, 1):
                            print(f"    {Colors.RED}{i}.{Colors.RESET} {exp['module']} → {exp['target']} ({exp['cve']})")
                        return exploits
        except Exception:
            pass

        # Fallback: CVE-to-MSF mapping
        self.print_status("LLM unavailable, using CVE-to-MSF module lookup...", "warning")
        try:
            from core.msf_modules import search_modules
            for cve in all_cves[:30]:
                cve_id = cve.get('id', '')
                if cve_id:
                    matches = search_modules(cve_id)
                    for mod_name, mod_info in matches:
                        exploits.append({
                            'module': mod_name,
                            'target': mod_info.get('description', '')[:60],
                            'cve': cve_id,
                            'reasoning': f"Direct CVE match (CVSS {cve.get('cvss', '?')})"
                        })
        except Exception as e:
            self.print_status(f"MSF module lookup failed: {e}", "warning")

        if exploits:
            self.print_status(f"Found {len(exploits)} exploit matches", "success")
            for i, exp in enumerate(exploits[:10], 1):
                print(f"    {Colors.RED}{i}.{Colors.RESET} {exp['module']} ({exp['cve']})")
        else:
            self.print_status("No exploit matches found.", "info")

        return exploits

    def _generate_workflow_report(self, state):
        """Generate HTML report from workflow state."""
        target = state.get('target', 'unknown')

        # Build network_data from services
        network_data = None
        services = state.get('services', [])
        if services:
            network_data = [{
                'ip': target,
                'hostname': target,
                'os_guess': '-',
                'ports': services
            }]

        vuln_data = state.get('correlations') or None
        exploit_data = state.get('exploits') or None

        try:
            from core.report_generator import get_report_generator
            rg = get_report_generator()
            report_path = rg.generate_pentest_report(
                target=target,
                network_data=network_data,
                vuln_data=vuln_data,
                exploit_data=exploit_data
            )
            self.print_status(f"Report saved to {report_path}", "success")
            state['report'] = report_path
        except Exception as e:
            self.print_status(f"Report generation failed: {e}", "error")

    def _save_state(self, state, state_file):
        """Save workflow state to JSON."""
        try:
            # Make serializable - convert CVE objects if needed
            serializable = json.loads(json.dumps(state, default=str))
            with open(state_file, 'w') as f:
                json.dump(serializable, f, indent=2)
        except Exception:
            pass

    # =========================================================================
    # MAIN LOOP
    # =========================================================================

    def run(self):
        """Main menu loop."""
        while True:
            self.show_menu()

            try:
                choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

                if choice == "0":
                    break
                elif choice == "1":
                    target = input(f"\n{Colors.WHITE}  Target IP/hostname: {Colors.RESET}").strip()
                    if target:
                        self.run_workflow(target)
                elif choice == "2":
                    target = input(f"\n{Colors.WHITE}  Target IP/hostname: {Colors.RESET}").strip()
                    if target:
                        self.quick_scan(target)
                elif choice == "3":
                    self.resume_workflow()

            except (EOFError, KeyboardInterrupt):
                print()
                break


def run():
    """Module entry point."""
    runner = WorkflowRunner()
    runner.run()


if __name__ == "__main__":
    run()
