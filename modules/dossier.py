"""
AUTARCH Dossier Module
Manage and correlate OSINT investigation data

Create dossiers to associate related OSINT findings like email searches,
username scans, phone lookups, and custom notes.
"""

import os
import sys
import json
import glob
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# Module metadata
NAME = "Dossier"
DESCRIPTION = "Manage OSINT investigation dossiers"
AUTHOR = "darkHal Security Group"
VERSION = "1.0"
CATEGORY = "osint"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner


class DossierManager:
    """Manage OSINT investigation dossiers."""

    def __init__(self):
        from core.paths import get_dossiers_dir
        self.dossier_dir = get_dossiers_dir()
        self.dossier_dir.mkdir(exist_ok=True)
        self.current_dossier = None
        self.current_dossier_path = None

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    # ==================== DOSSIER OPERATIONS ====================

    def _generate_dossier_id(self, name: str) -> str:
        """Generate a unique dossier ID from name."""
        # Sanitize name for filename
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name.lower())
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{safe_name}_{timestamp}"

    def _get_dossier_path(self, dossier_id: str) -> Path:
        """Get path to dossier file."""
        return self.dossier_dir / f"{dossier_id}.json"

    def _create_empty_dossier(self, name: str, subject: str = "", notes: str = "") -> Dict:
        """Create a new empty dossier structure."""
        return {
            "meta": {
                "name": name,
                "subject": subject,
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat(),
                "notes": notes,
            },
            "identifiers": {
                "emails": [],
                "usernames": [],
                "phones": [],
                "real_names": [],
                "aliases": [],
            },
            "results": {
                "email_searches": [],
                "username_searches": [],
                "phone_searches": [],
            },
            "profiles": [],
            "custom_notes": [],
        }

    def save_dossier(self, dossier: Dict, path: Path) -> bool:
        """Save dossier to file."""
        try:
            dossier["meta"]["modified"] = datetime.now().isoformat()
            with open(path, 'w') as f:
                json.dump(dossier, f, indent=2)
            return True
        except Exception as e:
            self.print_status(f"Failed to save dossier: {e}", "error")
            return False

    def load_dossier(self, path: Path) -> Optional[Dict]:
        """Load dossier from file."""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            self.print_status(f"Failed to load dossier: {e}", "error")
            return None

    def list_dossiers(self) -> List[Dict]:
        """List all saved dossiers."""
        dossiers = []
        for file in self.dossier_dir.glob("*.json"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    dossiers.append({
                        "path": file,
                        "id": file.stem,
                        "name": data.get("meta", {}).get("name", "Unknown"),
                        "subject": data.get("meta", {}).get("subject", ""),
                        "created": data.get("meta", {}).get("created", ""),
                        "modified": data.get("meta", {}).get("modified", ""),
                        "profiles_count": len(data.get("profiles", [])),
                        "identifiers_count": sum(len(v) for v in data.get("identifiers", {}).values()),
                    })
            except:
                continue
        return sorted(dossiers, key=lambda x: x.get("modified", ""), reverse=True)

    # ==================== UI METHODS ====================

    def create_new_dossier(self):
        """Interactive dossier creation."""
        print(f"\n{Colors.BOLD}Create New Dossier{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        name = input(f"{Colors.WHITE}Dossier name: {Colors.RESET}").strip()
        if not name:
            self.print_status("Dossier name is required", "error")
            return

        subject = input(f"{Colors.WHITE}Subject (target name/identifier): {Colors.RESET}").strip()
        notes = input(f"{Colors.WHITE}Initial notes (optional): {Colors.RESET}").strip()

        # Create dossier
        dossier_id = self._generate_dossier_id(name)
        dossier_path = self._get_dossier_path(dossier_id)
        dossier = self._create_empty_dossier(name, subject, notes)

        # Prompt for initial identifiers
        print(f"\n{Colors.CYAN}Add initial identifiers (press Enter to skip):{Colors.RESET}")

        emails = input(f"{Colors.WHITE}  Email(s) (comma-separated): {Colors.RESET}").strip()
        if emails:
            dossier["identifiers"]["emails"] = [e.strip() for e in emails.split(",") if e.strip()]

        usernames = input(f"{Colors.WHITE}  Username(s) (comma-separated): {Colors.RESET}").strip()
        if usernames:
            dossier["identifiers"]["usernames"] = [u.strip() for u in usernames.split(",") if u.strip()]

        phones = input(f"{Colors.WHITE}  Phone(s) (comma-separated): {Colors.RESET}").strip()
        if phones:
            dossier["identifiers"]["phones"] = [p.strip() for p in phones.split(",") if p.strip()]

        real_names = input(f"{Colors.WHITE}  Real name(s) (comma-separated): {Colors.RESET}").strip()
        if real_names:
            dossier["identifiers"]["real_names"] = [n.strip() for n in real_names.split(",") if n.strip()]

        # Save dossier
        if self.save_dossier(dossier, dossier_path):
            self.print_status(f"Dossier created: {dossier_id}", "success")
            self.current_dossier = dossier
            self.current_dossier_path = dossier_path

            # Ask if user wants to open it
            open_now = input(f"\n{Colors.WHITE}Open dossier now? [{Colors.GREEN}y{Colors.WHITE}/{Colors.RED}n{Colors.WHITE}]: {Colors.RESET}").strip().lower()
            if open_now == 'y':
                self.view_dossier_detail(dossier, dossier_path)

    def view_dossiers_list(self):
        """Display list of saved dossiers."""
        print(f"\n{Colors.BOLD}Saved Dossiers{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        dossiers = self.list_dossiers()

        if not dossiers:
            self.print_status("No dossiers found. Create one with 'Start New'.", "warning")
            return

        for i, d in enumerate(dossiers, 1):
            created = d.get("created", "")[:10] if d.get("created") else "Unknown"
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {d['name']}")
            print(f"      {Colors.DIM}Subject: {d.get('subject') or 'N/A'}{Colors.RESET}")
            print(f"      {Colors.DIM}Created: {created} | Profiles: {d['profiles_count']} | Identifiers: {d['identifiers_count']}{Colors.RESET}")
            print()

        print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
        print()

        choice = input(f"{Colors.WHITE}Select dossier to view: {Colors.RESET}").strip()

        if choice == "0" or not choice:
            return

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(dossiers):
                selected = dossiers[idx]
                dossier = self.load_dossier(selected["path"])
                if dossier:
                    self.view_dossier_detail(dossier, selected["path"])
        except ValueError:
            self.print_status("Invalid selection", "error")

    def view_dossier_detail(self, dossier: Dict, dossier_path: Path):
        """View and manage a specific dossier."""
        self.current_dossier = dossier
        self.current_dossier_path = dossier_path

        while True:
            clear_screen()
            display_banner()

            meta = dossier.get("meta", {})
            identifiers = dossier.get("identifiers", {})
            results = dossier.get("results", {})
            profiles = dossier.get("profiles", [])

            print(f"{Colors.MAGENTA}{Colors.BOLD}  Dossier: {meta.get('name', 'Unknown')}{Colors.RESET}")
            print(f"{Colors.DIM}  Subject: {meta.get('subject') or 'N/A'}{Colors.RESET}")
            print(f"{Colors.DIM}  Created: {meta.get('created', '')[:19]}{Colors.RESET}")
            print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
            print()

            # Summary stats
            total_identifiers = sum(len(v) for v in identifiers.values())
            total_searches = sum(len(v) for v in results.values())

            print(f"  {Colors.CYAN}Summary:{Colors.RESET}")
            print(f"    Identifiers:  {total_identifiers}")
            print(f"    Searches:     {total_searches}")
            print(f"    Profiles:     {len(profiles)}")
            print()

            # Menu
            print(f"  {Colors.GREEN}View{Colors.RESET}")
            print(f"    {Colors.GREEN}[1]{Colors.RESET} View Identifiers")
            print(f"    {Colors.GREEN}[2]{Colors.RESET} View Search Results")
            print(f"    {Colors.GREEN}[3]{Colors.RESET} View Profiles")
            print(f"    {Colors.GREEN}[4]{Colors.RESET} View Notes")
            print()
            print(f"  {Colors.CYAN}Add{Colors.RESET}")
            print(f"    {Colors.CYAN}[5]{Colors.RESET} Add Identifier")
            print(f"    {Colors.CYAN}[6]{Colors.RESET} Import Search Results")
            print(f"    {Colors.CYAN}[7]{Colors.RESET} Add Profile Manually")
            print(f"    {Colors.CYAN}[8]{Colors.RESET} Add Note")
            print()
            print(f"  {Colors.YELLOW}Manage{Colors.RESET}")
            print(f"    {Colors.YELLOW}[E]{Colors.RESET} Edit Dossier Info")
            print(f"    {Colors.YELLOW}[X]{Colors.RESET} Export Dossier")
            print(f"    {Colors.RED}[D]{Colors.RESET} Delete Dossier")
            print()
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")
            print()

            choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

            if choice == "0":
                break
            elif choice == "1":
                self._view_identifiers(dossier)
            elif choice == "2":
                self._view_search_results(dossier)
            elif choice == "3":
                self._view_profiles(dossier)
            elif choice == "4":
                self._view_notes(dossier)
            elif choice == "5":
                self._add_identifier(dossier, dossier_path)
            elif choice == "6":
                self._import_search_results(dossier, dossier_path)
            elif choice == "7":
                self._add_profile_manually(dossier, dossier_path)
            elif choice == "8":
                self._add_note(dossier, dossier_path)
            elif choice == "e":
                self._edit_dossier_info(dossier, dossier_path)
            elif choice == "x":
                self._export_dossier(dossier)
            elif choice == "d":
                if self._delete_dossier(dossier_path):
                    break

    def _view_identifiers(self, dossier: Dict):
        """View all identifiers in dossier."""
        print(f"\n{Colors.BOLD}Identifiers{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        identifiers = dossier.get("identifiers", {})

        for id_type, values in identifiers.items():
            if values:
                print(f"  {Colors.CYAN}{id_type.replace('_', ' ').title()}:{Colors.RESET}")
                for v in values:
                    print(f"    - {v}")
                print()

        if not any(identifiers.values()):
            print(f"  {Colors.DIM}No identifiers added yet.{Colors.RESET}\n")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _view_search_results(self, dossier: Dict):
        """View search results summary."""
        print(f"\n{Colors.BOLD}Search Results{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        results = dossier.get("results", {})

        # Email searches
        email_searches = results.get("email_searches", [])
        if email_searches:
            print(f"  {Colors.CYAN}Email Searches ({len(email_searches)}):{Colors.RESET}")
            for search in email_searches:
                print(f"    - {search.get('email', 'N/A')} ({search.get('date', '')[:10]})")
            print()

        # Username searches
        username_searches = results.get("username_searches", [])
        if username_searches:
            print(f"  {Colors.CYAN}Username Searches ({len(username_searches)}):{Colors.RESET}")
            for search in username_searches:
                found_count = len(search.get("found", []))
                print(f"    - {search.get('username', 'N/A')}: {found_count} profiles found ({search.get('date', '')[:10]})")
            print()

        # Phone searches
        phone_searches = results.get("phone_searches", [])
        if phone_searches:
            print(f"  {Colors.CYAN}Phone Searches ({len(phone_searches)}):{Colors.RESET}")
            for search in phone_searches:
                print(f"    - {search.get('phone', 'N/A')} ({search.get('date', '')[:10]})")
            print()

        if not any([email_searches, username_searches, phone_searches]):
            print(f"  {Colors.DIM}No search results imported yet.{Colors.RESET}\n")

        # Option to view details
        if username_searches:
            view = input(f"\n{Colors.WHITE}View username search details? [{Colors.GREEN}y{Colors.WHITE}/{Colors.RED}n{Colors.WHITE}]: {Colors.RESET}").strip().lower()
            if view == 'y':
                self._view_username_search_details(username_searches)
        else:
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _view_username_search_details(self, username_searches: List[Dict]):
        """View detailed username search results."""
        print(f"\n{Colors.BOLD}Username Search Details{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        for i, search in enumerate(username_searches, 1):
            print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {search.get('username', 'N/A')}")

        choice = input(f"\n{Colors.WHITE}Select search to view (0 to cancel): {Colors.RESET}").strip()

        try:
            idx = int(choice) - 1
            if 0 <= idx < len(username_searches):
                search = username_searches[idx]
                print(f"\n{Colors.BOLD}Results for '{search.get('username', 'N/A')}'{Colors.RESET}")
                print(f"{Colors.DIM}Date: {search.get('date', 'N/A')}{Colors.RESET}")
                print(f"{Colors.DIM}Total checked: {search.get('total_checked', 'N/A')}{Colors.RESET}\n")

                for profile in search.get("found", []):
                    status_color = Colors.GREEN if profile.get("status") == "good" else Colors.YELLOW
                    print(f"  {status_color}[+]{Colors.RESET} {profile.get('name', 'Unknown')}")
                    print(f"      {Colors.DIM}{profile.get('url', 'N/A')}{Colors.RESET}")
                    if profile.get("rate"):
                        print(f"      {Colors.DIM}Rate: {profile.get('rate')}{Colors.RESET}")
                    print()
        except (ValueError, IndexError):
            pass

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _view_profiles(self, dossier: Dict):
        """View all collected profiles."""
        print(f"\n{Colors.BOLD}Profiles{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        profiles = dossier.get("profiles", [])

        if not profiles:
            print(f"  {Colors.DIM}No profiles collected yet.{Colors.RESET}\n")
            input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
            return

        # Group by category
        by_category = {}
        for p in profiles:
            cat = p.get("category", "other")
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(p)

        for category, cat_profiles in sorted(by_category.items()):
            print(f"  {Colors.CYAN}{category.title()} ({len(cat_profiles)}):{Colors.RESET}")
            for p in cat_profiles:
                status_color = Colors.GREEN if p.get("status") == "good" else Colors.YELLOW
                print(f"    {status_color}[+]{Colors.RESET} {p.get('name', 'Unknown')}")
                print(f"        {Colors.DIM}{p.get('url', 'N/A')}{Colors.RESET}")
            print()

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _view_notes(self, dossier: Dict):
        """View dossier notes."""
        print(f"\n{Colors.BOLD}Notes{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        # Main notes
        main_notes = dossier.get("meta", {}).get("notes", "")
        if main_notes:
            print(f"  {Colors.CYAN}Main Notes:{Colors.RESET}")
            print(f"    {main_notes}")
            print()

        # Custom notes
        custom_notes = dossier.get("custom_notes", [])
        if custom_notes:
            print(f"  {Colors.CYAN}Additional Notes:{Colors.RESET}")
            for note in custom_notes:
                print(f"    [{note.get('date', '')[:10]}] {note.get('text', '')}")
            print()

        if not main_notes and not custom_notes:
            print(f"  {Colors.DIM}No notes added yet.{Colors.RESET}\n")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _add_identifier(self, dossier: Dict, dossier_path: Path):
        """Add an identifier to dossier."""
        print(f"\n{Colors.BOLD}Add Identifier{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        print(f"  {Colors.GREEN}[1]{Colors.RESET} Email")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Username")
        print(f"  {Colors.GREEN}[3]{Colors.RESET} Phone")
        print(f"  {Colors.GREEN}[4]{Colors.RESET} Real Name")
        print(f"  {Colors.GREEN}[5]{Colors.RESET} Alias")
        print()

        choice = input(f"{Colors.WHITE}Select type: {Colors.RESET}").strip()

        type_map = {"1": "emails", "2": "usernames", "3": "phones", "4": "real_names", "5": "aliases"}

        if choice not in type_map:
            return

        id_type = type_map[choice]
        value = input(f"{Colors.WHITE}Enter value: {Colors.RESET}").strip()

        if value:
            if "identifiers" not in dossier:
                dossier["identifiers"] = {}
            if id_type not in dossier["identifiers"]:
                dossier["identifiers"][id_type] = []

            if value not in dossier["identifiers"][id_type]:
                dossier["identifiers"][id_type].append(value)
                self.save_dossier(dossier, dossier_path)
                self.print_status(f"Added {id_type[:-1]}: {value}", "success")
            else:
                self.print_status("Identifier already exists", "warning")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _import_search_results(self, dossier: Dict, dossier_path: Path):
        """Import search results from JSON files."""
        print(f"\n{Colors.BOLD}Import Search Results{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        print(f"  {Colors.GREEN}[1]{Colors.RESET} Import username search results (JSON)")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Import from file path")
        print(f"  {Colors.GREEN}[3]{Colors.RESET} Scan current directory for results")
        print()

        choice = input(f"{Colors.WHITE}Select: {Colors.RESET}").strip()

        if choice == "1" or choice == "2":
            file_path = input(f"{Colors.WHITE}Enter JSON file path: {Colors.RESET}").strip()
            if file_path and os.path.exists(file_path):
                self._import_from_file(dossier, dossier_path, file_path)
            else:
                self.print_status("File not found", "error")

        elif choice == "3":
            # Scan for *_profiles.json files
            json_files = glob.glob("*_profiles.json")
            if not json_files:
                self.print_status("No *_profiles.json files found in current directory", "warning")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                return

            print(f"\n  {Colors.CYAN}Found files:{Colors.RESET}")
            for i, f in enumerate(json_files, 1):
                print(f"    {Colors.GREEN}[{i}]{Colors.RESET} {f}")
            print()

            file_choice = input(f"{Colors.WHITE}Select file to import (0 to cancel): {Colors.RESET}").strip()
            try:
                idx = int(file_choice) - 1
                if 0 <= idx < len(json_files):
                    self._import_from_file(dossier, dossier_path, json_files[idx])
            except ValueError:
                pass

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _import_from_file(self, dossier: Dict, dossier_path: Path, file_path: str):
        """Import data from a specific file."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Detect file type and import
            if "username" in data and "found" in data:
                # Username search results
                username = data.get("username", "unknown")
                found = data.get("found", [])
                total_checked = data.get("total_checked", 0)

                # Add to results
                if "results" not in dossier:
                    dossier["results"] = {}
                if "username_searches" not in dossier["results"]:
                    dossier["results"]["username_searches"] = []

                search_entry = {
                    "username": username,
                    "date": datetime.now().isoformat(),
                    "total_checked": total_checked,
                    "found": found,
                    "source_file": file_path,
                }
                dossier["results"]["username_searches"].append(search_entry)

                # Also add username to identifiers if not present
                if username not in dossier.get("identifiers", {}).get("usernames", []):
                    if "identifiers" not in dossier:
                        dossier["identifiers"] = {}
                    if "usernames" not in dossier["identifiers"]:
                        dossier["identifiers"]["usernames"] = []
                    dossier["identifiers"]["usernames"].append(username)

                # Add found profiles to main profiles list
                if "profiles" not in dossier:
                    dossier["profiles"] = []

                added_profiles = 0
                for profile in found:
                    # Check if profile URL already exists
                    existing_urls = [p.get("url") for p in dossier["profiles"]]
                    if profile.get("url") not in existing_urls:
                        dossier["profiles"].append(profile)
                        added_profiles += 1

                self.save_dossier(dossier, dossier_path)
                self.print_status(f"Imported: {username} ({len(found)} profiles, {added_profiles} new)", "success")

            else:
                self.print_status("Unknown file format", "error")

        except json.JSONDecodeError:
            self.print_status("Invalid JSON file", "error")
        except Exception as e:
            self.print_status(f"Import failed: {e}", "error")

    def _add_profile_manually(self, dossier: Dict, dossier_path: Path):
        """Manually add a profile."""
        print(f"\n{Colors.BOLD}Add Profile Manually{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        name = input(f"{Colors.WHITE}Site/platform name: {Colors.RESET}").strip()
        url = input(f"{Colors.WHITE}Profile URL: {Colors.RESET}").strip()
        category = input(f"{Colors.WHITE}Category (social/forum/other): {Colors.RESET}").strip() or "other"
        notes = input(f"{Colors.WHITE}Notes (optional): {Colors.RESET}").strip()

        if name and url:
            profile = {
                "name": name,
                "url": url,
                "category": category,
                "status": "manual",
                "rate": "100%",
                "notes": notes,
                "added": datetime.now().isoformat(),
            }

            if "profiles" not in dossier:
                dossier["profiles"] = []

            dossier["profiles"].append(profile)
            self.save_dossier(dossier, dossier_path)
            self.print_status(f"Added profile: {name}", "success")
        else:
            self.print_status("Name and URL are required", "error")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _add_note(self, dossier: Dict, dossier_path: Path):
        """Add a note to dossier."""
        print(f"\n{Colors.BOLD}Add Note{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        note_text = input(f"{Colors.WHITE}Enter note: {Colors.RESET}").strip()

        if note_text:
            if "custom_notes" not in dossier:
                dossier["custom_notes"] = []

            dossier["custom_notes"].append({
                "date": datetime.now().isoformat(),
                "text": note_text,
            })

            self.save_dossier(dossier, dossier_path)
            self.print_status("Note added", "success")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _edit_dossier_info(self, dossier: Dict, dossier_path: Path):
        """Edit dossier metadata."""
        print(f"\n{Colors.BOLD}Edit Dossier Info{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        meta = dossier.get("meta", {})

        print(f"  Current name: {meta.get('name', '')}")
        new_name = input(f"{Colors.WHITE}New name (Enter to keep): {Colors.RESET}").strip()
        if new_name:
            dossier["meta"]["name"] = new_name

        print(f"  Current subject: {meta.get('subject', '')}")
        new_subject = input(f"{Colors.WHITE}New subject (Enter to keep): {Colors.RESET}").strip()
        if new_subject:
            dossier["meta"]["subject"] = new_subject

        print(f"  Current notes: {meta.get('notes', '')}")
        new_notes = input(f"{Colors.WHITE}New notes (Enter to keep): {Colors.RESET}").strip()
        if new_notes:
            dossier["meta"]["notes"] = new_notes

        self.save_dossier(dossier, dossier_path)
        self.print_status("Dossier info updated", "success")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _export_dossier(self, dossier: Dict):
        """Export dossier to various formats."""
        print(f"\n{Colors.BOLD}Export Dossier{Colors.RESET}")
        print(f"{Colors.DIM}{'─' * 50}{Colors.RESET}\n")

        name = dossier.get("meta", {}).get("name", "dossier")
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in name.lower())

        print(f"  {Colors.GREEN}[1]{Colors.RESET} Export as JSON")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Export as Text Report")
        print()

        choice = input(f"{Colors.WHITE}Select format: {Colors.RESET}").strip()

        if choice == "1":
            filename = f"{safe_name}_export.json"
            with open(filename, 'w') as f:
                json.dump(dossier, f, indent=2)
            self.print_status(f"Exported to {filename}", "success")

        elif choice == "2":
            filename = f"{safe_name}_report.txt"
            self._export_text_report(dossier, filename)
            self.print_status(f"Exported to {filename}", "success")

        input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

    def _export_text_report(self, dossier: Dict, filename: str):
        """Export dossier as text report."""
        meta = dossier.get("meta", {})
        identifiers = dossier.get("identifiers", {})
        profiles = dossier.get("profiles", [])

        lines = [
            "=" * 60,
            f"AUTARCH DOSSIER REPORT",
            "=" * 60,
            "",
            f"Name:     {meta.get('name', 'N/A')}",
            f"Subject:  {meta.get('subject', 'N/A')}",
            f"Created:  {meta.get('created', 'N/A')}",
            f"Modified: {meta.get('modified', 'N/A')}",
            "",
            "-" * 60,
            "IDENTIFIERS",
            "-" * 60,
        ]

        for id_type, values in identifiers.items():
            if values:
                lines.append(f"\n{id_type.replace('_', ' ').title()}:")
                for v in values:
                    lines.append(f"  - {v}")

        lines.extend([
            "",
            "-" * 60,
            f"PROFILES ({len(profiles)})",
            "-" * 60,
        ])

        for p in profiles:
            lines.append(f"\n[{p.get('category', 'other')}] {p.get('name', 'Unknown')}")
            lines.append(f"  URL: {p.get('url', 'N/A')}")
            if p.get('status'):
                lines.append(f"  Status: {p.get('status')} ({p.get('rate', 'N/A')})")

        # Notes
        notes = dossier.get("custom_notes", [])
        if notes or meta.get("notes"):
            lines.extend([
                "",
                "-" * 60,
                "NOTES",
                "-" * 60,
            ])
            if meta.get("notes"):
                lines.append(f"\n{meta.get('notes')}")
            for note in notes:
                lines.append(f"\n[{note.get('date', '')[:10]}] {note.get('text', '')}")

        lines.extend([
            "",
            "=" * 60,
            "Generated by AUTARCH - darkHal Security Group",
            "=" * 60,
        ])

        with open(filename, 'w') as f:
            f.write("\n".join(lines))

    def _delete_dossier(self, dossier_path: Path) -> bool:
        """Delete a dossier."""
        confirm = input(f"\n{Colors.RED}Are you sure you want to delete this dossier? [{Colors.WHITE}yes{Colors.RED}/{Colors.WHITE}no{Colors.RED}]: {Colors.RESET}").strip().lower()

        if confirm == "yes":
            try:
                os.remove(dossier_path)
                self.print_status("Dossier deleted", "success")
                input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")
                return True
            except Exception as e:
                self.print_status(f"Failed to delete: {e}", "error")

        return False

    # ==================== MAIN MENU ====================

    def show_menu(self):
        clear_screen()
        display_banner()

        print(f"{Colors.MAGENTA}{Colors.BOLD}  Dossier Manager{Colors.RESET}")
        print(f"{Colors.DIM}  Manage OSINT investigation dossiers{Colors.RESET}")
        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        # Show stats
        dossiers = self.list_dossiers()
        print(f"  {Colors.DIM}Saved dossiers: {len(dossiers)}{Colors.RESET}")
        print()

        print(f"  {Colors.GREEN}[1]{Colors.RESET} Start New Dossier")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} View Dossiers")
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
                    self.create_new_dossier()
                elif choice == "2":
                    self.view_dossiers_list()

            except (EOFError, KeyboardInterrupt):
                break


def run():
    DossierManager().run()


if __name__ == "__main__":
    run()
