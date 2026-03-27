"""
AUTARCH Recon Module
Open Source Intelligence (OSINT) gathering

Domain, IP, email, username, and phone reconnaissance tools.
Integrates with social-analyzer for social media analysis.
Uses unified sites database from sherlock, maigret, and social-analyzer.
"""

import os
import sys
import subprocess
import socket
import re
import json
import time
import concurrent.futures
import urllib.request
from pathlib import Path
from urllib.parse import urlparse, quote
from typing import List, Dict, Optional, Tuple
from random import randint
from datetime import datetime

# Module metadata
DESCRIPTION = "OSINT & reconnaissance tools"
AUTHOR = "darkHal"
VERSION = "2.3"
CATEGORY = "osint"

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.banner import Colors, clear_screen, display_banner
from core.sites_db import get_sites_db
from core.report_generator import get_report_generator
from core.config import get_config


class Recon:
    """OSINT and reconnaissance tools."""

    def __init__(self):
        self.social_analyzer_available = self._check_social_analyzer()
        self.sites_db = get_sites_db()
        self.config = get_config()
        osint_settings = self.config.get_osint_settings()
        self.scan_config = {
            'max_sites': 200,
            'include_nsfw': osint_settings['include_nsfw'],
            'categories': None,  # None = all categories
            'timeout': osint_settings['timeout'],
            'threads': osint_settings['max_threads'],
        }

    def _check_social_analyzer(self) -> bool:
        """Check if social-analyzer is installed."""
        try:
            result = subprocess.run(
                "social-analyzer --help",
                shell=True,
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def print_status(self, message: str, status: str = "info"):
        colors = {"info": Colors.CYAN, "success": Colors.GREEN, "warning": Colors.YELLOW, "error": Colors.RED}
        symbols = {"info": "*", "success": "+", "warning": "!", "error": "X"}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def run_cmd(self, cmd: str, timeout: int = 30) -> tuple:
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0, result.stdout.strip()
        except:
            return False, ""

    # ==================== EMAIL OSINT ====================

    def email_lookup(self):
        """Email address OSINT."""
        print(f"\n{Colors.BOLD}Email OSINT{Colors.RESET}")
        email = input(f"{Colors.WHITE}Enter email address: {Colors.RESET}").strip()

        if not email or '@' not in email:
            self.print_status("Invalid email address", "error")
            return

        username, domain = email.split('@')

        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Target: {email}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Email format analysis
        print(f"{Colors.CYAN}Email Analysis:{Colors.RESET}")
        print(f"  Username:  {username}")
        print(f"  Domain:    {domain}")

        # Check if domain has MX records
        success, output = self.run_cmd(f"dig +short MX {domain}")
        if success and output:
            print(f"  Mail Svr:  {output.split()[1] if len(output.split()) > 1 else output}")
        else:
            print(f"  Mail Svr:  {Colors.YELLOW}No MX record{Colors.RESET}")

        # Breach check resources
        print(f"\n{Colors.CYAN}Breach Check Resources:{Colors.RESET}")
        print(f"  HaveIBeenPwned: https://haveibeenpwned.com/account/{quote(email)}")
        print(f"  DeHashed:       https://dehashed.com/search?query={quote(email)}")
        print(f"  IntelX:         https://intelx.io/?s={quote(email)}")

        # Email validation
        print(f"\n{Colors.CYAN}Email Validation:{Colors.RESET}")
        # Check common patterns
        disposable_domains = ['tempmail', 'throwaway', 'guerrilla', 'mailinator', '10minute']
        is_disposable = any(d in domain.lower() for d in disposable_domains)
        print(f"  Disposable:    {'Yes' if is_disposable else 'No'}")

        # Gravatar check
        import hashlib
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        print(f"  Gravatar:      https://gravatar.com/avatar/{email_hash}")

        # Related accounts lookup
        print(f"\n{Colors.CYAN}Account Search:{Colors.RESET}")
        print(f"  Google:        https://www.google.com/search?q=\"{quote(email)}\"")
        print(f"  GitHub:        https://api.github.com/search/users?q={quote(email)}+in:email")

    def email_permutator(self):
        """Generate email permutations."""
        print(f"\n{Colors.BOLD}Email Permutator{Colors.RESET}")
        first_name = input(f"{Colors.WHITE}First name: {Colors.RESET}").strip().lower()
        last_name = input(f"{Colors.WHITE}Last name: {Colors.RESET}").strip().lower()
        domain = input(f"{Colors.WHITE}Domain (e.g., company.com): {Colors.RESET}").strip().lower()

        if not first_name or not last_name or not domain:
            return

        # Generate permutations
        permutations = [
            f"{first_name}.{last_name}@{domain}",
            f"{first_name}{last_name}@{domain}",
            f"{last_name}.{first_name}@{domain}",
            f"{last_name}{first_name}@{domain}",
            f"{first_name[0]}{last_name}@{domain}",
            f"{first_name}{last_name[0]}@{domain}",
            f"{first_name[0]}.{last_name}@{domain}",
            f"{first_name}.{last_name[0]}@{domain}",
            f"{last_name}@{domain}",
            f"{first_name}@{domain}",
            f"{first_name}_{last_name}@{domain}",
            f"{first_name}-{last_name}@{domain}",
        ]

        print(f"\n{Colors.CYAN}Generated Email Permutations:{Colors.RESET}\n")
        for email in permutations:
            print(f"  {email}")

        # Save option
        save = input(f"\n{Colors.WHITE}Save to file? (y/n): {Colors.RESET}").strip().lower()
        if save == 'y':
            filename = f"{first_name}_{last_name}_emails.txt"
            with open(filename, 'w') as f:
                f.write('\n'.join(permutations))
            self.print_status(f"Saved to {filename}", "success")

    # ==================== USERNAME OSINT ====================

    # WAF/Captcha detection - only specific challenge page indicators
    WAF_PATTERNS = re.compile(
        r'captcha-info|Completing the CAPTCHA|'
        r'cf-browser-verification|cf_chl_prog|'
        r'ddos protection by|verify you are human|'
        r'please turn javascript on|enable cookies to continue',
        re.IGNORECASE
    )

    WAF_TITLE_PATTERNS = re.compile(
        r'just a moment|attention required|'
        r'ddos-guard|security check required',
        re.IGNORECASE
    )

    # Detection strings - return "false" means if found, user does NOT exist
    # Detection strings - return "true" means if found, user EXISTS
    SHARED_DETECTIONS = {
        'mastodon': [
            {'return': False, 'string': "The page you are looking for isn"},
            {'return': True, 'string': 'profile:username'},
            {'return': True, 'string': '/@{username}'},
        ],
        'discourse': [
            {'return': True, 'string': 'og:title'},
            {'return': True, 'string': '"{username}"'},
        ],
        'gitlab': [
            {'return': True, 'string': 'user-profile'},
        ],
        'phpbb': [
            {'return': False, 'string': 'No user'},
            {'return': True, 'string': 'memberlist'},
        ],
        'xenforo': [
            {'return': False, 'string': 'The requested member could not be found'},
            {'return': True, 'string': 'member-header'},
        ],
        'vbulletin': [
            {'return': False, 'string': 'is not a member'},
            {'return': True, 'string': 'profile-header'},
        ],
    }

    # Common patterns indicating user does NOT exist (return: false)
    # Prioritized by specificity - more specific patterns first
    NOT_FOUND_STRINGS = [
        # Very specific "not found" phrases
        'user not found', 'profile not found', 'account not found',
        'member not found', 'page not found', 'no user found',
        'does not exist', 'doesn\'t exist', 'no such user',
        'could not be found', 'cannot be found', 'user doesn\'t exist',
        'the specified member cannot be found',
        'the requested user is not valid',
        'this user is not registered',
        'this username is available', 'username is available',
        'claim this username', 'this name is available',
        # Account status
        'user has been deleted', 'account has been suspended',
        'account has been deleted', 'user has been banned',
        'this account has been suspended', 'account is suspended',
        'this profile is no longer available',
        # Soft 404 phrases
        'there\'s nothing here', 'this page is no longer available',
        'the page you are looking for isn\'t here',
        'hmm...this page doesn\'t exist', 'oops! page not found',
        'sorry, nobody on reddit goes by that name',
        'something went wrong', 'we couldn\'t find',
        # Registration/signup prompts (indicates username available)
        'create an account', 'sign up now', 'register now',
        'join now', 'create your account',
    ]

    # Patterns that strongly indicate user EXISTS (return: true)
    # These should be profile-specific elements
    FOUND_STRINGS = [
        # Profile metadata
        'og:title', 'profile:username', 'og:profile',
        # Profile structure indicators
        'user-profile', 'member-header', 'profile-header',
        'profile-info', 'user-info', 'profile-content',
        'profile-card', 'user-card', 'member-card',
        # User statistics
        'followers', 'following', 'subscribers', 'friends',
        'member since', 'joined', 'last seen', 'last active',
        'total posts', 'reputation', 'karma', 'cake day',
        # Action buttons (only appear on real profiles)
        'send message', 'private message', 'follow user',
        'add friend', 'block user', 'report user',
        # Verified indicators
        'verified account', 'verified user',
    ]

    # Site-specific detection patterns (like cupidcr4wl's data)
    # Format: domain -> {check_text: [...], not_found_text: [...]}
    SITE_PATTERNS = {
        # Social Media
        'reddit.com': {
            'check_text': ['karma', 'cake day', 'trophy-case'],
            'not_found_text': ['sorry, nobody on reddit goes by that name', 'page not found'],
        },
        'twitter.com': {
            'check_text': ['followers', 'following', 'data-testid="UserName"'],
            'not_found_text': ['this account doesn\'t exist', 'account suspended'],
        },
        'x.com': {
            'check_text': ['followers', 'following', 'data-testid="UserName"'],
            'not_found_text': ['this account doesn\'t exist', 'account suspended'],
        },
        'instagram.com': {
            'check_text': ['followers', 'following', 'edge_owner_to_timeline_media'],
            'not_found_text': ['sorry, this page isn\'t available'],
        },
        'tiktok.com': {
            'check_text': ['followers', 'following', 'likes'],
            'not_found_text': ['couldn\'t find this account'],
        },
        'github.com': {
            'check_text': ['contributions', 'repositories', 'gist-summary'],
            'not_found_text': ['not found'],
        },
        'youtube.com': {
            'check_text': ['subscribers', 'channel-header'],
            'not_found_text': ['this page isn\'t available'],
        },
        # Forums
        'forums.': {
            'check_text': ['member since', 'posts:', 'joined:', 'post count'],
            'not_found_text': ['member not found', 'no user', 'user doesn\'t exist'],
        },
        # Adult/Cam sites
        'chaturbate.com': {
            'check_text': ['broadcaster_gender', 'room_status', 'bio', 'following'],
            'not_found_text': ['http 404', 'page not found', 'bio page not available'],
        },
        'onlyfans.com': {
            'check_text': ['subscribersCount', '@'],
            'not_found_text': ['sorry, this page is not available'],
        },
        'fansly.com': {
            'check_text': ['followers', 'subscribersCount'],
            'not_found_text': ['not found'],
        },
        'pornhub.com': {
            'check_text': ['subscribers', 'video views', 'profile-info'],
            'not_found_text': ['page not found', '404'],
        },
        'xvideos.com': {
            'check_text': ['subscribers', 'video views'],
            'not_found_text': ['not found'],
        },
        'stripchat.com': {
            'check_text': ['followers', 'bio'],
            'not_found_text': ['not found', 'model not found'],
        },
        # Art/Creative
        'deviantart.com': {
            'check_text': ['watchers', 'deviations', 'gallery'],
            'not_found_text': ['this deviant doesn\'t exist'],
        },
        'artstation.com': {
            'check_text': ['followers', 'following', 'likes'],
            'not_found_text': ['not found'],
        },
        'furaffinity.net': {
            'check_text': ['submissions', 'favorites', 'watchers'],
            'not_found_text': ['user not found', 'the user you specified could not be found'],
        },
        'e621.net': {
            'check_text': ['favorites', 'uploads'],
            'not_found_text': ['not found'],
        },
        # Gaming
        'twitch.tv': {
            'check_text': ['followers', 'channel-header'],
            'not_found_text': ['sorry, unless you\'ve got a time machine'],
        },
        'steam': {
            'check_text': ['recent activity', 'level'],
            'not_found_text': ['specified profile could not be found'],
        },
        # Dating
        'fetlife.com': {
            'check_text': ['role:', 'orientation:', 'looking for:'],
            'not_found_text': ['user not found', 'the page you requested'],
        },
    }

    # Tracker/aggregator sites to deprioritize (not the real site)
    TRACKER_DOMAINS = [
        'tracker', 'stats', 'lookup', 'checker', 'finder', 'search',
        'viewer', 'imginn', 'picuki', 'dumpor', 'smihub', 'tumbral',
        'gramho', 'pixwox', 'instastories', 'storiesig', 'insta',
        'webstagram', 'vibbi', 'picbear', 'sometag', 'mulpix',
    ]

    # Common false positive URLs to skip
    FALSE_POSITIVE_URLS = [
        '/login', '/signin', '/signup', '/register', '/join',
        '/404', '/error', '/not-found', '/notfound',
        '/search', '/home', '/index', '/welcome',
    ]

    # Site-specific cookies for age verification and consent
    SITE_COOKIES = {
        'chaturbate.com': 'agreeterms=1; age_verified=1',
        'stripchat.com': 'age_confirmed=true',
        'bongacams.com': 'bonga_age=true',
        'cam4.com': 'age_checked=true',
        'myfreecams.com': 'mfc_age_check=1',
        'camsoda.com': 'age_verified=1',
        'livejasmin.com': 'age_gate=true',
        'pornhub.com': 'age_verified=1; accessAgeDisclaimerPH=1',
        'xvideos.com': 'age_verified=1',
        'xhamster.com': 'age_check=1',
        'xnxx.com': 'age_verified=1',
        'redtube.com': 'age_verified=1',
        'youporn.com': 'age_verified=1',
        'spankbang.com': 'age_verified=1',
        'eporner.com': 'age_verified=1',
        'fapster.xxx': 'age_verified=1',
        'rule34.xxx': 'age_gate=1',
        'e621.net': 'age_check=1',
        'furaffinity.net': 'sfw=0',
        'inkbunny.net': 'age_check=1',
        'hentai-foundry.com': 'age_check=1',
        'f95zone.to': 'xf_logged_in=1',
        'imgsrc.ru': 'lang=en; over18=1',
        'fansly.com': 'age_verified=1',
        'onlyfans.com': 'age_verified=1',
        'fetlife.com': 'age_check=1',
    }

    # Random User-Agent rotation to avoid detection
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]

    @staticmethod
    def validate_username(username: str) -> Tuple[bool, str]:
        """Validate username before searching (like Snoop).

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not username:
            return False, "Username cannot be empty"

        if len(username) < 2:
            return False, "Username too short (minimum 2 characters)"

        if len(username) > 100:
            return False, "Username too long (maximum 100 characters)"

        # Check for obviously invalid characters
        invalid_chars = set('<>{}[]|\\^~`')
        if any(c in username for c in invalid_chars):
            return False, f"Username contains invalid characters: {invalid_chars}"

        # If it looks like an email, extract the username part
        if '@' in username and '.' in username.split('@')[-1]:
            return True, "email"  # Signal this is an email

        return True, "ok"

    def _get_site_patterns(self, domain: str) -> Optional[Dict]:
        """Get site-specific detection patterns for a domain."""
        domain_lower = domain.lower()
        for pattern_domain, patterns in self.SITE_PATTERNS.items():
            if pattern_domain in domain_lower:
                return patterns
        return None

    def _check_site(self, site: Dict, username: str, retry: int = 0) -> Optional[Dict]:
        """Check if username exists on a site using CupidCr4wl-style detection.

        Detection logic (following CupidCr4wl pattern):
        1. If status 200 + error_string found → NOT FOUND (return None)
        2. If status 200 + match_string found → FOUND (green)
        3. If status 200 + neither matched → POSSIBLE (yellow)
        4. If status == error_code → NOT FOUND (return None)
        5. Response URL redirect detection for response_url/redirection types
        """
        try:
            # Random delay to avoid rate limiting (like Snoop)
            time.sleep(randint(10, 100) / 1000)

            url = site['url'].replace('{}', username)

            # Build request with rotating User-Agent
            # NOTE: Don't request gzip encoding - urllib doesn't auto-decompress it
            headers = {
                'User-Agent': self.USER_AGENTS[randint(0, len(self.USER_AGENTS) - 1)],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            if site.get('headers'):
                headers.update(site['headers'])

            # Add site-specific cookies for age verification
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            for cookie_domain, cookies in self.SITE_COOKIES.items():
                if cookie_domain in domain:
                    headers['Cookie'] = cookies
                    break

            req = urllib.request.Request(url, headers=headers)

            # Get detection info from database
            error_type = site.get('error_type', 'status_code')
            error_code = site.get('error_code')
            error_string = site.get('error_string', '').strip() if site.get('error_string') else None
            match_code = site.get('match_code')
            match_string = site.get('match_string', '').strip() if site.get('match_string') else None

            # Get site-specific patterns
            site_patterns = self._get_site_patterns(domain)

            try:
                with urllib.request.urlopen(req, timeout=self.scan_config['timeout']) as response:
                    status_code = response.getcode()
                    final_url = response.geturl()
                    resp_headers = {k.lower(): v.lower() for k, v in response.headers.items()}

                    raw_content = response.read()
                    try:
                        content = raw_content.decode('utf-8', errors='ignore')
                    except:
                        content = raw_content.decode('latin-1', errors='ignore')

                    content_lower = content.lower()
                    content_len = len(content)

                    # === WAF/Captcha Detection ===
                    is_filtered = False

                    # Extract title for analysis
                    title = ''
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', content, re.IGNORECASE)
                    if title_match:
                        title = title_match.group(1).strip()

                    # Check for Cloudflare challenge page (not just Cloudflare-served sites)
                    cf_challenge_patterns = [
                        'just a moment', 'checking your browser', 'please wait',
                        'ray id', 'cf-browser-verification', 'cf_chl_opt',
                        'enable javascript and cookies', 'why do i have to complete a captcha',
                    ]
                    if any(p in content_lower for p in cf_challenge_patterns):
                        is_filtered = True

                    # Check for actual WAF block patterns in content
                    if self.WAF_PATTERNS.search(content):
                        # Only flag if it's a short page (likely error/block page)
                        if content_len < 5000:
                            is_filtered = True

                    # Check title for WAF patterns (challenge pages have distinctive titles)
                    if title and self.WAF_TITLE_PATTERNS.search(title):
                        # "Just a moment..." is Cloudflare challenge
                        if 'moment' in title.lower() or 'attention' in title.lower() or 'blocked' in title.lower():
                            is_filtered = True

                    if is_filtered:
                        return {
                            'name': site['name'],
                            'url': url,
                            'category': site.get('category', 'other'),
                            'status': 'filtered',
                            'rate': '0%',
                            'title': 'filtered',
                        }

                    # === CupidCr4wl-Style Detection System ===
                    username_lower = username.lower()

                    # Collect all not_found and check texts
                    not_found_texts = []
                    check_texts = []

                    # 1. Add database patterns
                    if error_string:
                        not_found_texts.append(error_string.lower())
                    if match_string:
                        # Handle {username} placeholder
                        check_texts.append(
                            match_string.replace('{username}', username)
                            .replace('{account}', username).lower()
                        )

                    # 2. Add site-specific patterns
                    if site_patterns:
                        not_found_texts.extend([s.lower() for s in site_patterns.get('not_found_text', [])])
                        check_texts.extend([s.lower() for s in site_patterns.get('check_text', [])])

                    # 3. Detection based on error_type
                    # --- Status code detection ---
                    if error_type == 'status_code':
                        if error_code and status_code == error_code:
                            return None  # Expected "not found" status code
                        if status_code >= 400:
                            return None  # Error status

                    # --- Response URL / Redirect detection ---
                    if error_type in ('response_url', 'redirection'):
                        # Check if redirected away from profile page
                        if final_url != url and username_lower not in final_url.lower():
                            # Check if redirected to login/error page
                            final_lower = final_url.lower()
                            if any(fp in final_lower for fp in self.FALSE_POSITIVE_URLS):
                                return None
                            # Redirected to different page - likely not found
                            if domain not in final_lower:
                                return None

                    # === Pattern Matching (CupidCr4wl style) ===
                    not_found_matched = []
                    check_matched = []

                    # Check not_found_texts
                    for nf_text in not_found_texts:
                        if nf_text and nf_text in content_lower:
                            not_found_matched.append(nf_text)

                    # Check check_texts
                    for c_text in check_texts:
                        if c_text and c_text in content_lower:
                            check_matched.append(c_text)

                    # Fallback: check generic NOT_FOUND_STRINGS if no specific patterns
                    if not not_found_texts:
                        for nf_string in self.NOT_FOUND_STRINGS:
                            if nf_string.lower() in content_lower:
                                not_found_matched.append(nf_string)
                                break  # One is enough

                    # Fallback: check generic FOUND_STRINGS if no specific patterns
                    if not check_texts:
                        for f_string in self.FOUND_STRINGS:
                            check_str = f_string.replace('{username}', username_lower).lower()
                            if check_str in content_lower:
                                check_matched.append(f_string)

                    # === Determine Result (CupidCr4wl logic) ===
                    # Priority: not_found_text match beats everything
                    if not_found_matched:
                        # Not found text was found - user doesn't exist
                        return None

                    # Username presence check
                    username_in_content = username_lower in content_lower
                    username_in_title = username_lower in title.lower() if title else False

                    # Calculate confidence
                    found_indicators = len(check_matched)
                    if username_in_content:
                        found_indicators += 1
                    if username_in_title:
                        found_indicators += 1

                    # Determine status
                    if check_matched and (username_in_content or username_in_title):
                        # check_text matched AND username found → FOUND (green)
                        status = 'good'
                        rate = min(100, 60 + (found_indicators * 10))
                    elif check_matched:
                        # check_text matched but username not explicitly found → POSSIBLE (yellow)
                        status = 'maybe'
                        rate = 50 + (found_indicators * 10)
                    elif username_in_content and status_code == 200:
                        # No patterns matched but username in content with 200 → POSSIBLE
                        status = 'maybe'
                        rate = 40 + (found_indicators * 5)
                    elif status_code == 200 and content_len > 1000:
                        # Got 200 with substantial content but no matches → LOW confidence
                        status = 'maybe'
                        rate = 30
                    else:
                        # Nothing matched
                        return None

                    # === Additional Validation ===

                    # Very short pages are usually error pages
                    if content_len < 500 and not check_matched:
                        if not username_in_content:
                            return None

                    # Check for tracker sites
                    url_lower = url.lower()
                    is_tracker = any(t in url_lower for t in self.TRACKER_DOMAINS)

                    # Minimum threshold
                    if rate < 30:
                        return None

                    return {
                        'name': site['name'],
                        'url': url,
                        'category': site.get('category', 'other'),
                        'rate': f'{rate}%',
                        'status': status,
                        'title': title[:100] if title else '',
                        'is_tracker': is_tracker,
                        'check_matched': len(check_matched),
                        'not_found_matched': len(not_found_matched),
                        'error_type': error_type,
                        'has_pattern': bool(error_string or match_string or site_patterns),
                    }

            except urllib.error.HTTPError as e:
                # Handle HTTP errors using database patterns
                if error_code and e.code == error_code:
                    # Expected "not found" code from database
                    return None
                if e.code == 404:
                    return None
                if e.code in [403, 401]:
                    return {
                        'name': site['name'],
                        'url': url,
                        'category': site.get('category', 'other'),
                        'status': 'restricted',
                        'rate': '?',
                    }
                # Retry on 5xx errors
                if e.code >= 500 and retry < 2:
                    time.sleep(1)
                    return self._check_site(site, username, retry + 1)
                return None

            except urllib.error.URLError as e:
                # Retry on connection errors
                if retry < 2:
                    time.sleep(1)
                    return self._check_site(site, username, retry + 1)
                return None

            except Exception:
                return None

        except Exception:
            return None

        return None

    def username_lookup(self):
        """Username OSINT across platforms using sites database."""
        print(f"\n{Colors.BOLD}Username OSINT{Colors.RESET}")

        # Show database stats
        db_stats = self.sites_db.get_stats()
        print(f"{Colors.DIM}Database: {db_stats['total_sites']} sites available{Colors.RESET}\n")

        username = input(f"{Colors.WHITE}Enter username: {Colors.RESET}").strip()
        if not username:
            return

        # Validate username
        is_valid, validation_msg = self.validate_username(username)
        if not is_valid:
            self.print_status(validation_msg, "error")
            return

        # If it's an email, ask if they want to extract username
        if validation_msg == "email":
            email_username = username.split('@')[0]
            use_email_user = input(f"{Colors.WHITE}Detected email. Use '{email_username}' as username? (y/n): {Colors.RESET}").strip().lower()
            if use_email_user == 'y':
                username = email_username
                print(f"{Colors.CYAN}[*] Using username: {username}{Colors.RESET}")

        # Scan type selection
        print(f"\n{Colors.CYAN}Scan Type:{Colors.RESET}")
        print(f"  {Colors.GREEN}[1]{Colors.RESET} Quick scan (top 100 sites)")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Standard scan (500 sites)")
        print(f"  {Colors.GREEN}[3]{Colors.RESET} Full scan (all {db_stats['enabled_sites']} sites)")
        print(f"  {Colors.GREEN}[4]{Colors.RESET} Custom scan (by category)")

        scan_choice = input(f"\n{Colors.WHITE}Select [1-4]: {Colors.RESET}").strip()

        max_sites = 100
        categories = None
        # Use config setting as default
        osint_settings = self.config.get_osint_settings()
        include_nsfw = osint_settings['include_nsfw']

        if scan_choice == '2':
            max_sites = 500
        elif scan_choice == '3':
            max_sites = 99999  # All sites
        elif scan_choice == '4':
            # Category selection
            cats = self.sites_db.get_categories()
            print(f"\n{Colors.CYAN}Available Categories:{Colors.RESET}")
            for i, (cat, count) in enumerate(cats, 1):
                print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {cat} ({count} sites)")

            cat_input = input(f"\n{Colors.WHITE}Enter category numbers (comma-separated): {Colors.RESET}").strip()
            try:
                indices = [int(x.strip()) - 1 for x in cat_input.split(',')]
                categories = [cats[i][0] for i in indices if 0 <= i < len(cats)]
            except:
                categories = None
            max_sites = 99999

        # NSFW option (default from config)
        if db_stats['nsfw_sites'] > 0:
            default_nsfw = 'y' if include_nsfw else 'n'
            nsfw_choice = input(f"{Colors.WHITE}Include NSFW sites? (y/n) [{Colors.GREEN if include_nsfw else Colors.DIM}{default_nsfw}{Colors.WHITE}]: {Colors.RESET}").strip().lower()
            if nsfw_choice:  # Only change if user provided input
                include_nsfw = nsfw_choice == 'y'

        print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}Target Username: {username}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}\n")

        # Get sites from database
        sites = self.sites_db.get_sites_for_scan(
            categories=categories,
            include_nsfw=include_nsfw,
            max_sites=max_sites
        )

        total_sites = len(sites)
        est_time = (total_sites * self.scan_config['timeout']) // self.scan_config['threads'] // 60
        print(f"{Colors.CYAN}[*] Scanning {total_sites} sites with {self.scan_config['threads']} threads...{Colors.RESET}")
        print(f"{Colors.DIM}    (Estimated time: {est_time}-{est_time*2} minutes for full scan){Colors.RESET}\n")

        found = []
        checked = 0
        errors = 0
        scan_start = time.time()

        # Multi-threaded scanning
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.scan_config['threads']) as executor:
                future_to_site = {executor.submit(self._check_site, site, username): site for site in sites}

                for future in concurrent.futures.as_completed(future_to_site):
                    site = future_to_site[future]
                    checked += 1

                    # Show current site being checked (verbose)
                    print(f"\r{Colors.DIM}  [{checked}/{total_sites}] Checking: {site['name'][:30]:30}{Colors.RESET}", end='', flush=True)

                    try:
                        result = future.result()

                        if result:
                            found.append(result)
                            status = result.get('status', '')
                            rate = result.get('rate', '0%')
                            is_tracker = result.get('is_tracker', False)

                            # Clear the checking line and display result
                            print(f"\r{' ' * 60}\r", end='')

                            # Display based on status (social-analyzer style)
                            if status == 'filtered':
                                pass  # Don't show filtered/WAF blocked
                            elif status == 'restricted':
                                pass  # Don't show restricted in real-time, summarize later
                            elif status == 'good':
                                marker = f"{Colors.DIM}[tracker]{Colors.RESET} " if is_tracker else ""
                                print(f"  {Colors.GREEN}[+]{Colors.RESET} {result['name']:25} {marker}{result['url']} {Colors.GREEN}[{rate}]{Colors.RESET}")
                            elif status == 'maybe' and not is_tracker:
                                print(f"  {Colors.YELLOW}[?]{Colors.RESET} {result['name']:25} {result['url']} {Colors.YELLOW}[{rate}]{Colors.RESET}")
                            # 'bad' status not shown in real-time
                    except Exception as e:
                        errors += 1

                    # Progress indicator every 100 sites
                    if checked % 100 == 0:
                        print(f"\r{' ' * 60}\r{Colors.DIM}  ... progress: {checked}/{total_sites} sites checked, {len(found)} found{Colors.RESET}")

            # Clear the last checking line
            print(f"\r{' ' * 60}\r", end='')

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.RESET}")

        # Summary
        print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}Results Summary{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")
        print(f"  Sites in scan:  {total_sites}")
        print(f"  Sites checked:  {checked}")
        print(f"  Profiles found: {Colors.GREEN}{len(found)}{Colors.RESET}")
        if errors > 0:
            print(f"  Errors:         {Colors.YELLOW}{errors}{Colors.RESET}")

        if found:
            # Categorize results (social-analyzer style: good/maybe/bad)
            good = [f for f in found if f.get('status') == 'good']
            maybe = [f for f in found if f.get('status') == 'maybe']
            bad = [f for f in found if f.get('status') == 'bad']
            restricted = [f for f in found if f.get('status') == 'restricted']
            filtered = [f for f in found if f.get('status') == 'filtered']

            # Separate trackers from real sites
            good_real = [f for f in good if not f.get('is_tracker')]
            good_trackers = [f for f in good if f.get('is_tracker')]
            maybe_real = [f for f in maybe if not f.get('is_tracker')]

            # Count pattern-based detections
            pattern_based = [f for f in found if f.get('has_pattern')]
            generic_based = [f for f in found if not f.get('has_pattern')]

            print(f"\n{Colors.CYAN}Results Breakdown:{Colors.RESET}")
            print(f"  {Colors.GREEN}Detected (good):{Colors.RESET}     {len(good_real)}")
            print(f"  {Colors.YELLOW}Unknown (maybe):{Colors.RESET}     {len(maybe_real)}")
            print(f"  {Colors.DIM}Bad (low rate):{Colors.RESET}      {len(bad)}")
            print(f"  {Colors.DIM}Restricted (403):{Colors.RESET}    {len(restricted)}")
            print(f"  {Colors.DIM}Filtered (WAF):{Colors.RESET}      {len(filtered)}")
            print(f"  {Colors.DIM}Tracker sites:{Colors.RESET}       {len(good_trackers)}")

            print(f"\n{Colors.CYAN}Detection Method:{Colors.RESET}")
            print(f"  {Colors.GREEN}Pattern-based:{Colors.RESET}      {len(pattern_based)} (from database)")
            print(f"  {Colors.DIM}Generic fallback:{Colors.RESET}   {len(generic_based)}")

            # Group detected by category
            by_cat = {}
            for f in good_real:
                cat = f.get('category', 'other')
                if cat not in by_cat:
                    by_cat[cat] = []
                by_cat[cat].append(f)

            if by_cat:
                print(f"\n{Colors.CYAN}Detected by Category:{Colors.RESET}")
                for cat, items in sorted(by_cat.items(), key=lambda x: -len(x[1])):
                    print(f"  {cat}: {len(items)}")

            # Show detected profiles (good status)
            if good_real:
                print(f"\n{Colors.GREEN}{'─' * 40}{Colors.RESET}")
                print(f"{Colors.GREEN}Detected Profiles:{Colors.RESET}")
                print(f"{Colors.GREEN}{'─' * 40}{Colors.RESET}")
                for r in sorted(good_real, key=lambda x: x['name'].lower())[:20]:
                    print(f"  [{r.get('rate', '?')}] {r['name']}: {r['url']}")

            # Show unknown profiles (maybe status)
            if maybe_real:
                print(f"\n{Colors.YELLOW}{'─' * 40}{Colors.RESET}")
                print(f"{Colors.YELLOW}Unknown (may exist):{Colors.RESET}")
                print(f"{Colors.YELLOW}{'─' * 40}{Colors.RESET}")
                for r in sorted(maybe_real, key=lambda x: x['name'].lower())[:15]:
                    print(f"  [{r.get('rate', '?')}] {r['name']}: {r['url']}")

            # Option to show restricted
            if restricted:
                show_restricted = input(f"\n{Colors.WHITE}Show {len(restricted)} restricted results? (y/n): {Colors.RESET}").strip().lower()
                if show_restricted == 'y':
                    print(f"\n{Colors.YELLOW}Restricted (may exist, access denied):{Colors.RESET}")
                    for r in restricted[:30]:
                        print(f"  [?] {r['name']}: {r['url']}")

            # Save option
            save = input(f"\n{Colors.WHITE}Save results? [{Colors.GREEN}1{Colors.WHITE}] JSON [{Colors.GREEN}2{Colors.WHITE}] HTML [{Colors.GREEN}3{Colors.WHITE}] Both [{Colors.RED}n{Colors.WHITE}] No: {Colors.RESET}").strip().lower()
            if save in ['1', '2', '3']:
                if save in ['1', '3']:
                    filename = f"{username}_profiles.json"
                    with open(filename, 'w') as f:
                        json.dump({'username': username, 'found': found, 'total_checked': checked}, f, indent=2)
                    self.print_status(f"Saved JSON to {filename}", "success")

                if save in ['2', '3']:
                    # Generate HTML report
                    reporter = get_report_generator()
                    scan_time = time.time() - scan_start
                    report_path = reporter.generate_username_report(
                        username=username,
                        results=found,
                        total_checked=checked,
                        scan_time=scan_time
                    )
                    self.print_status(f"Saved HTML report to {report_path}", "success")

    def social_analyzer_search(self, username: str):
        """Run social-analyzer on a username."""
        if not self.social_analyzer_available:
            self.print_status("social-analyzer not installed. Install with: pip install social-analyzer", "warning")
            return

        print(f"\n{Colors.CYAN}Running social-analyzer...{Colors.RESET}")
        print(f"{Colors.DIM}This may take a few minutes...{Colors.RESET}\n")

        # Run social-analyzer
        cmd = f"social-analyzer --username '{username}' --metadata --output json 2>/dev/null"
        success, output = self.run_cmd(cmd, timeout=300)

        if success and output:
            try:
                results = json.loads(output)
                detected = results.get('detected', [])

                if detected:
                    print(f"{Colors.GREEN}Found {len(detected)} profiles:{Colors.RESET}\n")
                    for profile in detected[:20]:
                        site = profile.get('site', 'Unknown')
                        link = profile.get('link', '')
                        print(f"  {Colors.GREEN}+{Colors.RESET} {site:20} {link}")
                else:
                    print(f"{Colors.YELLOW}No profiles detected{Colors.RESET}")
            except json.JSONDecodeError:
                print(output)  # Show raw output
        else:
            self.print_status("social-analyzer scan completed (check for results)", "info")

    # ==================== PHONE OSINT ====================

    def phone_lookup(self):
        """Phone number OSINT."""
        print(f"\n{Colors.BOLD}Phone Number OSINT{Colors.RESET}")
        print(f"{Colors.DIM}Enter with country code (e.g., +1234567890){Colors.RESET}\n")

        phone = input(f"{Colors.WHITE}Enter phone number: {Colors.RESET}").strip()

        if not phone:
            return

        # Clean phone number
        phone_clean = re.sub(r'[^\d+]', '', phone)

        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Target: {phone_clean}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Parse phone number
        print(f"{Colors.CYAN}Number Analysis:{Colors.RESET}")

        # Country code detection
        country_codes = {
            '+1': 'USA/Canada', '+44': 'UK', '+49': 'Germany', '+33': 'France',
            '+81': 'Japan', '+86': 'China', '+91': 'India', '+7': 'Russia',
            '+61': 'Australia', '+55': 'Brazil', '+34': 'Spain', '+39': 'Italy'
        }

        country = 'Unknown'
        for code, name in country_codes.items():
            if phone_clean.startswith(code):
                country = name
                break

        print(f"  Country:   {country}")
        print(f"  Format:    {phone_clean}")

        # Carrier lookup resources
        print(f"\n{Colors.CYAN}Carrier Lookup:{Colors.RESET}")
        print(f"  NumVerify: https://numverify.com/")
        print(f"  Twilio:    https://www.twilio.com/lookup")

        # Search resources
        print(f"\n{Colors.CYAN}Search Resources:{Colors.RESET}")
        print(f"  TrueCaller:    https://www.truecaller.com/search/{quote(phone_clean)}")
        print(f"  Sync.me:       https://sync.me/search/?number={quote(phone_clean)}")
        print(f"  SpyDialer:     https://www.spydialer.com/")
        print(f"  WhitePages:    https://www.whitepages.com/phone/{quote(phone_clean)}")
        print(f"  Google:        https://www.google.com/search?q=\"{quote(phone_clean)}\"")

        # Messaging apps check
        print(f"\n{Colors.CYAN}Messaging Apps (manual check):{Colors.RESET}")
        print(f"  - WhatsApp: Add to contacts and check profile")
        print(f"  - Telegram: Search by phone number")
        print(f"  - Signal: Check if registered")

        # CallerID spam check
        print(f"\n{Colors.CYAN}Spam/Scam Check:{Colors.RESET}")
        print(f"  https://www.shouldianswer.com/phone-number/{phone_clean.replace('+', '')}")

    # ==================== DOMAIN/IP (from original) ====================

    def domain_info(self):
        """Gather domain information."""
        print(f"\n{Colors.BOLD}Domain Reconnaissance{Colors.RESET}")
        domain = input(f"{Colors.WHITE}Enter domain: {Colors.RESET}").strip()

        if not domain:
            return

        if '://' in domain:
            domain = urlparse(domain).netloc
        domain = domain.split('/')[0]

        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Target: {domain}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # DNS Resolution
        print(f"{Colors.CYAN}DNS Records:{Colors.RESET}")
        try:
            ip = socket.gethostbyname(domain)
            print(f"  A Record:    {ip}")
        except:
            print(f"  A Record:    {Colors.RED}Not found{Colors.RESET}")

        for record_type in ['MX', 'NS', 'TXT']:
            success, output = self.run_cmd(f"dig +short {record_type} {domain} 2>/dev/null")
            if success and output:
                records = output.split('\n')[:3]
                print(f"  {record_type} Record:  {records[0]}")

        # WHOIS
        print(f"\n{Colors.CYAN}WHOIS Information:{Colors.RESET}")
        success, output = self.run_cmd(f"whois {domain} 2>/dev/null")
        if success and output:
            important = ['Registrar:', 'Creation Date:', 'Expiration Date:', 'Name Server:', 'Organization:']
            for line in output.split('\n'):
                for key in important:
                    if key.lower() in line.lower():
                        print(f"  {line.strip()}")
                        break

        # Subdomains
        print(f"\n{Colors.CYAN}Subdomains (via crt.sh):{Colors.RESET}")
        success, output = self.run_cmd(f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' 2>/dev/null | head -5000")
        if success and output:
            try:
                certs = json.loads(output)
                subdomains = set()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        if sub and '*' not in sub:
                            subdomains.add(sub)

                for sub in sorted(subdomains)[:15]:
                    print(f"  {sub}")
                if len(subdomains) > 15:
                    print(f"  {Colors.DIM}... and {len(subdomains) - 15} more{Colors.RESET}")
            except:
                pass

    def ip_info(self):
        """Gather IP address information."""
        print(f"\n{Colors.BOLD}IP Address Reconnaissance{Colors.RESET}")
        ip = input(f"{Colors.WHITE}Enter IP address: {Colors.RESET}").strip()

        if not ip:
            return

        try:
            socket.inet_aton(ip)
        except:
            self.print_status("Invalid IP address", "error")
            return

        print(f"\n{Colors.CYAN}{'─' * 50}{Colors.RESET}")
        print(f"{Colors.BOLD}Target: {ip}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        # Reverse DNS
        print(f"{Colors.CYAN}Reverse DNS:{Colors.RESET}")
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"  Hostname: {hostname}")
        except:
            print(f"  Hostname: {Colors.DIM}Not found{Colors.RESET}")

        # GeoIP
        print(f"\n{Colors.CYAN}Geolocation:{Colors.RESET}")
        success, output = self.run_cmd(f"curl -s 'http://ip-api.com/json/{ip}' 2>/dev/null")
        if success and output:
            try:
                data = json.loads(output)
                print(f"  Country:  {data.get('country', 'Unknown')}")
                print(f"  Region:   {data.get('regionName', 'Unknown')}")
                print(f"  City:     {data.get('city', 'Unknown')}")
                print(f"  ISP:      {data.get('isp', 'Unknown')}")
                print(f"  Org:      {data.get('org', 'Unknown')}")
            except:
                pass

        # Quick port scan
        print(f"\n{Colors.CYAN}Quick Port Scan:{Colors.RESET}")
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                print(f"  {port}/tcp open")
            sock.close()

    def subdomain_enum(self):
        """Enumerate subdomains."""
        print(f"\n{Colors.BOLD}Subdomain Enumeration{Colors.RESET}")
        domain = input(f"{Colors.WHITE}Enter domain: {Colors.RESET}").strip()

        if not domain:
            return

        if '://' in domain:
            domain = urlparse(domain).netloc

        print(f"\n{Colors.CYAN}Enumerating subdomains for {domain}...{Colors.RESET}\n")

        subdomains = set()

        # Certificate Transparency
        self.print_status("Checking certificate transparency logs...", "info")
        success, output = self.run_cmd(f"curl -s 'https://crt.sh/?q=%.{domain}&output=json' 2>/dev/null")
        if success and output:
            try:
                certs = json.loads(output)
                for cert in certs:
                    name = cert.get('name_value', '')
                    for sub in name.split('\n'):
                        if sub and '*' not in sub and domain in sub:
                            subdomains.add(sub.strip())
            except:
                pass

        # Common subdomains
        self.print_status("Checking common subdomains...", "info")
        common_subs = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2',
            'vpn', 'api', 'dev', 'staging', 'test', 'blog', 'shop', 'admin',
            'portal', 'secure', 'app', 'mobile', 'cdn', 'static', 'assets'
        ]

        for sub in common_subs:
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                subdomains.add(fqdn)
            except:
                pass

        print(f"\n{Colors.GREEN}Found {len(subdomains)} subdomains:{Colors.RESET}\n")
        for sub in sorted(subdomains):
            try:
                ip = socket.gethostbyname(sub)
                print(f"  {sub:40} -> {ip}")
            except:
                print(f"  {sub}")

    def tech_detect(self):
        """Detect technologies on a website."""
        print(f"\n{Colors.BOLD}Technology Detection{Colors.RESET}")
        url = input(f"{Colors.WHITE}Enter URL: {Colors.RESET}").strip()

        if not url:
            return

        if not url.startswith('http'):
            url = f"https://{url}"

        print(f"\n{Colors.CYAN}Analyzing {url}...{Colors.RESET}\n")

        # Fetch headers
        success, output = self.run_cmd(f"curl -sI '{url}' 2>/dev/null")
        if success and output:
            print(f"{Colors.CYAN}HTTP Headers:{Colors.RESET}")
            for line in output.split('\n'):
                if ':' in line:
                    key = line.split(':')[0].lower()
                    if key in ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']:
                        print(f"  {line.strip()}")

            techs = []
            output_lower = output.lower()
            if 'nginx' in output_lower: techs.append("Nginx")
            if 'apache' in output_lower: techs.append("Apache")
            if 'cloudflare' in output_lower: techs.append("Cloudflare")
            if 'php' in output_lower: techs.append("PHP")

            if techs:
                print(f"\n{Colors.CYAN}Detected:{Colors.RESET}")
                for tech in techs:
                    print(f"  {Colors.GREEN}+{Colors.RESET} {tech}")

    # ==================== TOOLS ====================

    def run_geoip_module(self):
        """Run the GEO IP/Domain Lookup module."""
        try:
            from modules.geoip import run as geoip_run
            geoip_run()
        except ImportError as e:
            self.print_status(f"Failed to load GEO IP module: {e}", "error")
        except Exception as e:
            self.print_status(f"Error running GEO IP module: {e}", "error")

    def run_yandex_module(self):
        """Run the Yandex OSINT module."""
        try:
            from modules.yandex_osint import run as yandex_run
            yandex_run()
        except ImportError as e:
            self.print_status(f"Failed to load Yandex OSINT module: {e}", "error")
        except Exception as e:
            self.print_status(f"Error running Yandex OSINT module: {e}", "error")

    def run_network_test(self):
        """Run the Network Test module."""
        try:
            from modules.nettest import run as nettest_run
            nettest_run()
        except ImportError as e:
            self.print_status(f"Failed to load Network Test module: {e}", "error")
        except Exception as e:
            self.print_status(f"Error running Network Test module: {e}", "error")

    def run_snoop_decoder(self):
        """Run the Snoop Database Decoder module."""
        try:
            from modules.snoop_decoder import run as snoop_run
            snoop_run()
        except ImportError as e:
            self.print_status(f"Failed to load Snoop Decoder: {e}", "error")
        except Exception as e:
            self.print_status(f"Error running Snoop Decoder: {e}", "error")

    def run_dossier_manager(self):
        """Run the Dossier Manager module."""
        try:
            from modules.dossier import run as dossier_run
            dossier_run()
        except ImportError as e:
            self.print_status(f"Failed to load Dossier Manager: {e}", "error")
        except Exception as e:
            self.print_status(f"Error running Dossier Manager: {e}", "error")

    def show_sites_db_stats(self):
        """Display sites database statistics."""
        print(f"\n{Colors.BOLD}Sites Database Statistics{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        stats = self.sites_db.get_stats()
        coverage = self.sites_db.get_detection_coverage()

        print(f"  {Colors.CYAN}Database Path:{Colors.RESET} {stats['db_path']}")
        print(f"  {Colors.CYAN}Database Size:{Colors.RESET} {stats['db_size_mb']:.2f} MB")
        print()
        print(f"  {Colors.GREEN}Total Sites:{Colors.RESET}   {stats['total_sites']:,}")
        print(f"  {Colors.GREEN}Enabled:{Colors.RESET}       {stats['enabled_sites']:,}")
        print(f"  {Colors.RED}NSFW Sites:{Colors.RESET}    {stats['nsfw_sites']:,}")

        # Detection coverage section
        print(f"\n  {Colors.CYAN}Detection Coverage:{Colors.RESET}")
        print(f"    With detection type:  {stats['with_detection']:>5,} ({coverage.get('pct_error_type', 0):.1f}%)")
        print(f"    With error string:    {coverage['with_error_string']:>5,} ({coverage.get('pct_error_string', 0):.1f}%)")
        print(f"    With match string:    {coverage['with_match_string']:>5,} ({coverage.get('pct_match_string', 0):.1f}%)")

        # By error type
        if stats.get('by_error_type'):
            print(f"\n  {Colors.CYAN}By Detection Method:{Colors.RESET}")
            for etype, count in sorted(stats['by_error_type'].items(), key=lambda x: -x[1]):
                bar = '█' * min(int(count / 200), 25)
                print(f"    {etype:20} {count:>5,}  {Colors.MAGENTA}{bar}{Colors.RESET}")

        print(f"\n  {Colors.CYAN}By Source:{Colors.RESET}")
        for source, count in sorted(stats['by_source'].items(), key=lambda x: -x[1]):
            bar = '█' * min(int(count / 200), 30)
            print(f"    {source:20} {count:>5,}  {Colors.GREEN}{bar}{Colors.RESET}")

        print(f"\n  {Colors.CYAN}By Category:{Colors.RESET}")
        for cat, count in sorted(stats['by_category'].items(), key=lambda x: -x[1])[:10]:
            bar = '█' * min(int(count / 100), 30)
            print(f"    {cat:20} {count:>5,}  {Colors.BLUE}{bar}{Colors.RESET}")

    # ==================== NMAP SCANNER ====================

    def _check_nmap(self) -> bool:
        """Check if nmap is installed."""
        from core.paths import find_tool
        return find_tool('nmap') is not None

    def _run_nmap(self, target: str, flags: str, description: str, timeout: int = 300):
        """Run an nmap scan with live output and color coding."""
        if not target.strip():
            self.print_status("Target cannot be empty", "error")
            return

        cmd = f"nmap {flags} {target}"
        print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}Scan: {description}{Colors.RESET}")
        print(f"{Colors.DIM}Command: {cmd}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}\n")

        full_output = []
        open_ports = []

        try:
            proc = subprocess.Popen(
                cmd, shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )

            for raw_line in iter(proc.stdout.readline, b''):
                line = raw_line.decode('utf-8', errors='ignore').rstrip('\n')
                full_output.append(line)
                line_lower = line.lower()

                if 'open' in line_lower and ('tcp' in line_lower or 'udp' in line_lower or '/' in line):
                    print(f"  {Colors.GREEN}{line}{Colors.RESET}")
                    open_ports.append(line.strip())
                elif 'closed' in line_lower or 'filtered' in line_lower:
                    print(f"  {Colors.DIM}{line}{Colors.RESET}")
                elif 'nmap scan report' in line_lower:
                    print(f"  {Colors.CYAN}{Colors.BOLD}{line}{Colors.RESET}")
                else:
                    print(f"  {line}")

            proc.wait(timeout=timeout)

        except subprocess.TimeoutExpired:
            proc.kill()
            self.print_status("Scan timed out", "warning")
        except KeyboardInterrupt:
            proc.kill()
            self.print_status("Scan interrupted", "warning")
        except Exception as e:
            self.print_status(f"Scan error: {e}", "error")
            return

        # Summary
        print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
        if open_ports:
            print(f"{Colors.GREEN}{Colors.BOLD}Open ports found: {len(open_ports)}{Colors.RESET}")
            for p in open_ports:
                print(f"  {Colors.GREEN}  {p}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}No open ports found{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}")

        # Save option
        save = input(f"\n{Colors.WHITE}Save output to file? (y/n): {Colors.RESET}").strip().lower()
        if save == 'y':
            safe_target = re.sub(r'[^\w.\-]', '_', target)
            filename = f"{safe_target}_nmap.txt"
            with open(filename, 'w') as f:
                f.write('\n'.join(full_output))
            self.print_status(f"Saved to {filename}", "success")

    def nmap_scanner(self):
        """Nmap scanner submenu."""
        if not self._check_nmap():
            self.print_status("nmap is not installed", "error")
            return

        while True:
            print(f"\n{Colors.BOLD}Nmap Scanner{Colors.RESET}")
            print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}")
            print(f"  {Colors.GREEN}[1]{Colors.RESET} Top 100 Ports       - Fastest common port scan")
            print(f"  {Colors.GREEN}[2]{Colors.RESET} Quick Scan           - Default top 1000 ports")
            print(f"  {Colors.GREEN}[3]{Colors.RESET} Full TCP Scan        - All 65535 ports (slow)")
            print(f"  {Colors.GREEN}[4]{Colors.RESET} Stealth SYN Scan     - Half-open scan (needs root)")
            print(f"  {Colors.GREEN}[5]{Colors.RESET} Service Detection    - Detect service versions (-sV)")
            print(f"  {Colors.GREEN}[6]{Colors.RESET} OS Detection         - OS fingerprinting (needs root)")
            print(f"  {Colors.GREEN}[7]{Colors.RESET} Vulnerability Scan   - NSE vuln scripts")
            print(f"  {Colors.GREEN}[8]{Colors.RESET} UDP Scan             - Top 100 UDP ports (slow, needs root)")
            print(f"  {Colors.GREEN}[9]{Colors.RESET} Custom Scan          - Enter your own nmap flags")
            print(f"  {Colors.DIM}[0]{Colors.RESET} Back")

            choice = input(f"\n{Colors.WHITE}  Select: {Colors.RESET}").strip()

            if choice == "0":
                break

            presets = {
                "1": ("--top-ports 100 -T4", "Top 100 Ports"),
                "2": ("-T4", "Quick Scan (Top 1000)"),
                "3": ("-p- -T4", "Full TCP Scan (All 65535 Ports)"),
                "4": ("-sS -T4", "Stealth SYN Scan"),
                "5": ("-sV -T4", "Service Version Detection"),
                "6": ("-O -T4", "OS Detection"),
                "7": ("--script vuln -T4", "Vulnerability Scan"),
                "8": ("-sU --top-ports 100 -T4", "UDP Scan (Top 100)"),
            }

            if choice in presets:
                target = input(f"{Colors.WHITE}  Target IP/hostname: {Colors.RESET}").strip()
                if target:
                    flags, desc = presets[choice]
                    self._run_nmap(target, flags, desc)
            elif choice == "9":
                target = input(f"{Colors.WHITE}  Target IP/hostname: {Colors.RESET}").strip()
                if target:
                    flags = input(f"{Colors.WHITE}  Nmap flags: {Colors.RESET}").strip()
                    if flags:
                        self._run_nmap(target, flags, f"Custom Scan ({flags})")

    # ==================== NETWORK MAPPER ====================

    def network_mapper(self):
        """Network mapper - discover hosts and services on a subnet."""
        print(f"\n{Colors.BOLD}Network Mapper{Colors.RESET}")
        print(f"{Colors.DIM}Discover hosts and services on your network{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        print(f"  {Colors.GREEN}[1]{Colors.RESET} Enter subnet manually")
        print(f"  {Colors.GREEN}[A]{Colors.RESET} Auto-detect local subnet")
        print()

        choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip().lower()

        if choice == 'a':
            subnet = self._auto_detect_subnet()
            if not subnet:
                self.print_status("Could not auto-detect subnet", "error")
                return
            print(f"{Colors.CYAN}[*] Detected subnet: {subnet}{Colors.RESET}")
        elif choice == '1':
            subnet = input(f"{Colors.WHITE}Enter subnet (e.g., 192.168.1.0/24): {Colors.RESET}").strip()
            if not subnet:
                return
        else:
            return

        # Phase 1: Ping sweep
        self.print_status(f"Phase 1: Ping sweep on {subnet}...", "info")
        live_hosts = self._nmap_ping_sweep(subnet)

        if not live_hosts:
            self.print_status("No live hosts found", "warning")
            return

        self.print_status(f"Found {len(live_hosts)} live hosts", "success")

        # Phase 2: Service scan
        scan_services = input(f"{Colors.WHITE}Scan services on discovered hosts? (y/n) [{Colors.GREEN}y{Colors.WHITE}]: {Colors.RESET}").strip().lower()
        if scan_services == 'n':
            for ip in live_hosts:
                print(f"  {Colors.GREEN}+{Colors.RESET} {ip}")
            return

        self.print_status(f"Phase 2: Service detection on {len(live_hosts)} hosts...", "info")
        hosts = []
        for i, ip in enumerate(live_hosts, 1):
            print(f"\r{Colors.DIM}  [{i}/{len(live_hosts)}] Scanning {ip}...{Colors.RESET}", end='', flush=True)
            host_info = self._nmap_host_detail(ip)
            hosts.append(host_info)

        print(f"\r{' ' * 60}\r", end='')
        self._display_network_map(hosts, subnet)

    def _auto_detect_subnet(self) -> str:
        """Auto-detect the local subnet."""
        success, output = self.run_cmd("hostname -I")
        if success and output:
            local_ip = output.strip().split()[0]
            # Append /24
            parts = local_ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return ""

    def _nmap_ping_sweep(self, subnet: str) -> list:
        """Run nmap ping sweep to find live hosts."""
        success, output = self.run_cmd(f"nmap -sn {subnet}", timeout=120)
        if not success:
            return []

        hosts = []
        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                # Extract IP
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    hosts.append(ip_match.group(1))
        return hosts

    def _nmap_host_detail(self, ip: str) -> dict:
        """Get detailed service info for a single host."""
        result = {'ip': ip, 'hostname': '', 'os_guess': '', 'ports': []}

        success, output = self.run_cmd(f"nmap -sV --top-ports 20 -T4 {ip}", timeout=120)
        if not success:
            return result

        for line in output.split('\n'):
            if 'Nmap scan report for' in line:
                # Extract hostname
                hostname_match = re.search(r'for (\S+)\s+\(', line)
                if hostname_match:
                    result['hostname'] = hostname_match.group(1)

            port_match = re.match(r'\s*(\d+)/(tcp|udp)\s+(\S+)\s+(.*)', line)
            if port_match:
                result['ports'].append({
                    'port': int(port_match.group(1)),
                    'state': port_match.group(3),
                    'service': port_match.group(4).strip(),
                })

            if 'OS details:' in line:
                result['os_guess'] = line.split('OS details:')[1].strip()
            elif 'Service Info: OS:' in line:
                os_match = re.search(r'OS: ([^;]+)', line)
                if os_match:
                    result['os_guess'] = os_match.group(1).strip()

        return result

    def _display_network_map(self, hosts: list, subnet: str):
        """Display network map results and save."""
        print(f"\n{Colors.CYAN}{'─' * 75}{Colors.RESET}")
        print(f"{Colors.BOLD}Network Map: {subnet}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 75}{Colors.RESET}\n")

        print(f"  {'IP':<18} {'Hostname':<20} {'OS':<15} {'Open Ports'}")
        print(f"  {'─' * 70}")

        for host in hosts:
            ip = host['ip']
            hostname = host.get('hostname', '')[:18] or '-'
            os_guess = host.get('os_guess', '')[:13] or '-'
            open_ports = [p for p in host.get('ports', []) if p.get('state') == 'open']
            ports_str = ', '.join(f"{p['port']}" for p in open_ports[:6])
            if len(open_ports) > 6:
                ports_str += f" +{len(open_ports)-6} more"

            print(f"  {ip:<18} {hostname:<20} {os_guess:<15} {ports_str}")

            # Show services
            for p in open_ports[:6]:
                service = p.get('service', '')
                if service:
                    print(f"  {'':<18} {Colors.DIM}{p['port']:>5}/tcp  {service}{Colors.RESET}")

        # Save results
        os.makedirs("results", exist_ok=True)
        safe_subnet = re.sub(r'[^\w.\-]', '_', subnet)
        filename = f"results/network_map_{safe_subnet}.json"
        with open(filename, 'w') as f:
            json.dump({'subnet': subnet, 'hosts': hosts, 'timestamp': datetime.now().isoformat()}, f, indent=2)
        self.print_status(f"Saved to {filename}", "success")

    # ==================== WEB SCANNER ====================

    def web_scanner(self):
        """Web application security scanner."""
        print(f"\n{Colors.BOLD}Web Scanner{Colors.RESET}")
        print(f"{Colors.DIM}Check web applications for security issues{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        url = input(f"{Colors.WHITE}Enter URL: {Colors.RESET}").strip()
        if not url:
            return

        if not url.startswith('http'):
            url = f"https://{url}"

        parsed = urlparse(url)
        hostname = parsed.netloc

        print(f"\n{Colors.CYAN}Scanning {url}...{Colors.RESET}\n")

        all_findings = []

        # Header checks
        self.print_status("Checking HTTP headers...", "info")
        header_findings = self._web_check_headers(url)
        all_findings.extend(header_findings)

        # SSL check
        if parsed.scheme == 'https':
            self.print_status("Checking SSL/TLS...", "info")
            ssl_findings = self._web_check_ssl(hostname)
            all_findings.extend(ssl_findings)

        # Directory bruteforce
        self.print_status("Checking common paths...", "info")
        dir_findings = self._web_dir_bruteforce(url)
        all_findings.extend(dir_findings)

        # Display findings by severity
        print(f"\n{Colors.CYAN}{'─' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}Web Scanner Results: {url}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 60}{Colors.RESET}\n")

        high = [f for f in all_findings if f.get('severity') == 'HIGH']
        medium = [f for f in all_findings if f.get('severity') == 'MEDIUM']
        low = [f for f in all_findings if f.get('severity') == 'LOW']
        info = [f for f in all_findings if f.get('severity') == 'INFO']

        for sev, items, color in [('HIGH', high, Colors.RED), ('MEDIUM', medium, Colors.YELLOW),
                                   ('LOW', low, Colors.CYAN), ('INFO', info, Colors.DIM)]:
            if items:
                print(f"  {color}{Colors.BOLD}{sev} ({len(items)}){Colors.RESET}")
                for item in items:
                    print(f"  {color}  [{sev}]{Colors.RESET} {item['title']}")
                    if item.get('detail'):
                        print(f"         {Colors.DIM}{item['detail']}{Colors.RESET}")
                print()

        print(f"  {Colors.BOLD}Total findings: {len(all_findings)}{Colors.RESET}")
        print(f"  HIGH: {len(high)} | MEDIUM: {len(medium)} | LOW: {len(low)} | INFO: {len(info)}")

    def _web_check_headers(self, url: str) -> list:
        """Check HTTP response headers for security issues."""
        findings = []

        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': self.USER_AGENTS[0],
            })
            with urllib.request.urlopen(req, timeout=10) as response:
                headers = {k.lower(): v for k, v in response.headers.items()}

                # Server header
                if 'server' in headers:
                    findings.append({'title': f"Server header exposed: {headers['server']}", 'severity': 'LOW', 'detail': 'Consider hiding server version'})

                if 'x-powered-by' in headers:
                    findings.append({'title': f"X-Powered-By exposed: {headers['x-powered-by']}", 'severity': 'LOW', 'detail': 'Remove X-Powered-By header'})

                # Missing security headers
                security_headers = {
                    'strict-transport-security': ('HSTS missing', 'HIGH', 'Add Strict-Transport-Security header'),
                    'content-security-policy': ('CSP missing', 'HIGH', 'Add Content-Security-Policy header'),
                    'x-frame-options': ('X-Frame-Options missing', 'MEDIUM', 'Clickjacking protection missing'),
                    'x-content-type-options': ('X-Content-Type-Options missing', 'MEDIUM', 'Add nosniff header'),
                    'referrer-policy': ('Referrer-Policy missing', 'MEDIUM', 'Add Referrer-Policy header'),
                }

                for header, (title, severity, detail) in security_headers.items():
                    if header not in headers:
                        findings.append({'title': title, 'severity': severity, 'detail': detail})

                # Misconfigurations
                misconfig_findings = self._web_check_misconfigs(headers)
                findings.extend(misconfig_findings)

        except urllib.error.HTTPError as e:
            findings.append({'title': f"HTTP Error: {e.code}", 'severity': 'INFO', 'detail': str(e.reason)})
        except Exception as e:
            findings.append({'title': f"Connection error: {str(e)[:60]}", 'severity': 'INFO', 'detail': ''})

        return findings

    def _web_check_ssl(self, hostname: str) -> list:
        """Check SSL/TLS configuration."""
        findings = []

        success, output = self.run_cmd(
            f"echo | openssl s_client -connect {hostname}:443 -servername {hostname} 2>/dev/null",
            timeout=15
        )

        if not success or not output:
            findings.append({'title': 'SSL check failed or no HTTPS', 'severity': 'INFO', 'detail': ''})
            return findings

        # Check certificate details
        success2, cert_output = self.run_cmd(
            f"echo | openssl s_client -connect {hostname}:443 -servername {hostname} 2>/dev/null | openssl x509 -noout -dates -issuer -subject 2>/dev/null",
            timeout=15
        )

        if success2 and cert_output:
            for line in cert_output.split('\n'):
                if 'notAfter' in line:
                    expiry = line.split('=', 1)[1].strip() if '=' in line else ''
                    findings.append({'title': f"Certificate expires: {expiry}", 'severity': 'INFO', 'detail': ''})
                elif 'issuer' in line.lower():
                    findings.append({'title': f"Certificate issuer: {line.split('=', 1)[-1].strip()[:60]}", 'severity': 'INFO', 'detail': ''})

        # Check for weak protocols
        for protocol in ['ssl3', 'tls1', 'tls1_1']:
            success, _ = self.run_cmd(
                f"echo | openssl s_client -connect {hostname}:443 -{protocol} 2>/dev/null",
                timeout=10
            )
            if success:
                proto_name = protocol.replace('ssl3', 'SSLv3').replace('tls1_1', 'TLSv1.1').replace('tls1', 'TLSv1.0')
                findings.append({'title': f"Weak protocol supported: {proto_name}", 'severity': 'HIGH', 'detail': 'Disable legacy protocols'})

        return findings

    def _web_dir_bruteforce(self, url: str) -> list:
        """Check for common sensitive paths."""
        findings = []
        common_paths = [
            '.git/HEAD', '.env', '.htaccess', 'robots.txt', 'sitemap.xml',
            'admin/', 'wp-admin/', 'phpinfo.php', 'server-status', 'backup/',
            '.DS_Store', 'config.php', '.svn/', 'web.config', 'wp-login.php',
            '.well-known/security.txt', 'crossdomain.xml', 'elmah.axd',
            'wp-config.php.bak', 'dump.sql', 'database.sql', 'debug/',
            'api/', 'swagger-ui.html', 'graphql', '.git/config',
            'composer.json', 'package.json', '.env.bak', 'Dockerfile',
            'docker-compose.yml', 'readme.md',
        ]

        base_url = url.rstrip('/')

        for path in common_paths:
            try:
                check_url = f"{base_url}/{path}"
                req = urllib.request.Request(check_url, method='HEAD', headers={
                    'User-Agent': self.USER_AGENTS[0],
                })
                with urllib.request.urlopen(req, timeout=5) as response:
                    status = response.getcode()
                    if status in [200, 403]:
                        severity = 'HIGH' if path in ['.git/HEAD', '.env', '.git/config', 'dump.sql', 'database.sql'] else 'MEDIUM'
                        status_str = 'Found' if status == 200 else 'Forbidden'
                        findings.append({
                            'title': f"/{path} [{status}] {status_str}",
                            'severity': severity,
                            'detail': check_url,
                        })
            except:
                pass

        return findings

    def _web_check_misconfigs(self, headers: dict) -> list:
        """Check for common misconfigurations in headers."""
        findings = []

        # CORS wildcard
        acao = headers.get('access-control-allow-origin', '')
        if acao == '*':
            findings.append({'title': 'CORS wildcard: Access-Control-Allow-Origin: *', 'severity': 'MEDIUM', 'detail': 'Restrict CORS origins'})

        # Cookie security
        set_cookie = headers.get('set-cookie', '')
        if set_cookie:
            if 'secure' not in set_cookie.lower():
                findings.append({'title': 'Cookie missing Secure flag', 'severity': 'MEDIUM', 'detail': ''})
            if 'httponly' not in set_cookie.lower():
                findings.append({'title': 'Cookie missing HttpOnly flag', 'severity': 'MEDIUM', 'detail': ''})

        return findings

    # ==================== VULNERABILITY CORRELATOR ====================

    SERVICE_TO_CPE = {
        'apache': ('apache', 'http_server'),
        'nginx': ('f5', 'nginx'),
        'openssh': ('openbsd', 'openssh'),
        'openssl': ('openssl', 'openssl'),
        'mysql': ('oracle', 'mysql'),
        'mariadb': ('mariadb', 'mariadb'),
        'postgresql': ('postgresql', 'postgresql'),
        'postgres': ('postgresql', 'postgresql'),
        'samba': ('samba', 'samba'),
        'vsftpd': ('vsftpd_project', 'vsftpd'),
        'proftpd': ('proftpd_project', 'proftpd'),
        'postfix': ('postfix', 'postfix'),
        'dovecot': ('dovecot', 'dovecot'),
        'php': ('php', 'php'),
        'tomcat': ('apache', 'tomcat'),
        'iis': ('microsoft', 'internet_information_services'),
        'exim': ('exim', 'exim'),
        'bind': ('isc', 'bind'),
        'cups': ('apple', 'cups'),
        'redis': ('redis', 'redis'),
        'mongodb': ('mongodb', 'mongodb'),
        'elasticsearch': ('elastic', 'elasticsearch'),
        'jenkins': ('jenkins', 'jenkins'),
        'node': ('nodejs', 'node.js'),
    }

    def vuln_correlator(self):
        """Vulnerability correlator - match services to CVEs."""
        print(f"\n{Colors.BOLD}Vulnerability Correlator{Colors.RESET}")
        print(f"{Colors.DIM}Match detected services against CVE database{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 50}{Colors.RESET}\n")

        print(f"  {Colors.GREEN}[1]{Colors.RESET} Run fresh nmap -sV scan")
        print(f"  {Colors.GREEN}[2]{Colors.RESET} Load from Network Map JSON")
        print(f"  {Colors.GREEN}[3]{Colors.RESET} Load from nmap output file")
        print()

        choice = input(f"{Colors.WHITE}  Select: {Colors.RESET}").strip()

        services = []
        target = ""

        if choice == "1":
            target = input(f"{Colors.WHITE}Target IP/hostname: {Colors.RESET}").strip()
            if not target:
                return
            self.print_status(f"Running nmap -sV on {target}...", "info")
            success, output = self.run_cmd(f"nmap -sV -T4 {target}", timeout=300)
            if success:
                services = self._parse_nmap_services(output)
            else:
                self.print_status("nmap scan failed", "error")
                return

        elif choice == "2":
            # Load from network map JSON
            json_files = sorted(Path("results").glob("network_map_*.json")) if Path("results").exists() else []
            if not json_files:
                self.print_status("No network map files found. Run Network Mapper first.", "warning")
                return

            print(f"\n{Colors.CYAN}Available network maps:{Colors.RESET}")
            for i, f in enumerate(json_files, 1):
                print(f"  {Colors.GREEN}[{i}]{Colors.RESET} {f.name}")

            sel = input(f"\n{Colors.WHITE}Select: {Colors.RESET}").strip()
            try:
                idx = int(sel) - 1
                with open(json_files[idx], 'r') as f:
                    data = json.load(f)
                target = data.get('subnet', 'unknown')
                for host in data.get('hosts', []):
                    for port_info in host.get('ports', []):
                        if port_info.get('state') == 'open':
                            services.append({
                                'port': port_info['port'],
                                'protocol': 'tcp',
                                'service': port_info.get('service', ''),
                                'version': '',
                                'host': host['ip'],
                            })
                            # Try to parse service+version
                            svc = port_info.get('service', '')
                            parts = svc.split()
                            if len(parts) >= 2:
                                services[-1]['service'] = parts[0]
                                services[-1]['version'] = parts[1]
            except (ValueError, IndexError, json.JSONDecodeError) as e:
                self.print_status(f"Error loading file: {e}", "error")
                return

        elif choice == "3":
            filepath = input(f"{Colors.WHITE}Path to nmap output file: {Colors.RESET}").strip()
            if not filepath or not os.path.exists(filepath):
                self.print_status("File not found", "error")
                return
            with open(filepath, 'r') as f:
                output = f.read()
            services = self._parse_nmap_services(output)
            target = filepath

        if not services:
            self.print_status("No services found to correlate", "warning")
            return

        self.print_status(f"Found {len(services)} services, correlating with CVE database...", "info")

        # Correlate each service
        correlations = []
        try:
            from core.cve import get_cve_db
            cve_db = get_cve_db()
        except ImportError:
            self.print_status("CVE database module not available", "error")
            return

        for svc in services:
            cves = self._correlate_service(svc, cve_db)
            if cves:
                correlations.append({
                    'service': svc,
                    'cves': cves,
                })

        self._display_vuln_report(correlations, target)

    def _parse_nmap_services(self, nmap_output: str) -> list:
        """Parse nmap -sV output for services."""
        services = []
        port_re = re.compile(r'(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)')
        current_host = ''

        for line in nmap_output.split('\n'):
            if 'Nmap scan report for' in line:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                current_host = ip_match.group(1) if ip_match else ''

            m = port_re.match(line.strip())
            if m:
                service_full = m.group(4).strip()
                # Split product and version
                parts = service_full.split()
                product = parts[0] if parts else m.group(3)
                version = parts[1] if len(parts) > 1 else ''

                services.append({
                    'port': int(m.group(1)),
                    'protocol': m.group(2),
                    'service': product,
                    'version': version,
                    'host': current_host,
                })

        return services

    def _build_cpe(self, service: str, product: str, version: str) -> str:
        """Build a CPE string from service info."""
        service_lower = service.lower()
        product_lower = product.lower()

        # Try to find in lookup table
        for key, (vendor, prod) in self.SERVICE_TO_CPE.items():
            if key in service_lower or key in product_lower:
                cpe = f"cpe:2.3:a:{vendor}:{prod}"
                if version:
                    clean_ver = re.sub(r'[^0-9.]', '', version)
                    if clean_ver:
                        cpe += f":{clean_ver}"
                return cpe

        return ""

    def _correlate_service(self, service_info: dict, cve_db) -> list:
        """Correlate a service with CVEs from the database."""
        service = service_info.get('service', '')
        version = service_info.get('version', '')

        # Try CPE-based search
        cpe = self._build_cpe(service, service, version)
        cves = []

        if cpe:
            cves = cve_db.search_cves(cpe_pattern=cpe, max_results=20)

        # Fallback to keyword search
        if len(cves) < 5:
            keyword = f"{service} {version}".strip()
            keyword_cves = cve_db.search_cves(keyword=keyword, max_results=20)
            seen = {c['cve_id'] for c in cves}
            for c in keyword_cves:
                if c['cve_id'] not in seen:
                    cves.append(c)

        # Sort by CVSS score descending
        cves.sort(key=lambda x: x.get('cvss_score', 0) or 0, reverse=True)
        return cves[:15]

    def _display_vuln_report(self, correlations: list, target: str):
        """Display vulnerability correlation results."""
        print(f"\n{Colors.CYAN}{'─' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}Vulnerability Report: {target}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}\n")

        total_cves = 0
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for corr in correlations:
            svc = corr['service']
            cves = corr['cves']
            host = svc.get('host', '')
            port = svc.get('port', '')
            service_name = svc.get('service', '')
            version = svc.get('version', '')

            print(f"  {Colors.BOLD}{service_name}:{version}{Colors.RESET} on port {port} ({host})")

            for cve in cves:
                total_cves += 1
                score = cve.get('cvss_score', 0) or 0
                severity = cve.get('severity', 'UNKNOWN')
                cve_id = cve.get('cve_id', '')
                desc = (cve.get('description', '') or '')[:80]

                # Count and color
                if severity in severity_counts:
                    severity_counts[severity] += 1

                if severity in ('CRITICAL', 'HIGH'):
                    sev_color = Colors.RED
                elif severity == 'MEDIUM':
                    sev_color = Colors.YELLOW
                else:
                    sev_color = Colors.CYAN

                print(f"    {sev_color}{cve_id} ({severity} {score}){Colors.RESET} {desc}")

            print()

        # Summary
        print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}Summary:{Colors.RESET} {total_cves} CVEs across {len(correlations)} services")
        print(f"  CRITICAL: {severity_counts['CRITICAL']} | HIGH: {severity_counts['HIGH']} | MEDIUM: {severity_counts['MEDIUM']} | LOW: {severity_counts['LOW']}")

        # Save results
        if correlations:
            os.makedirs("results", exist_ok=True)
            safe_target = re.sub(r'[^\w.\-]', '_', str(target))
            filename = f"results/vuln_correlator_{safe_target}.json"
            save_data = {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'correlations': [
                    {
                        'service': c['service'],
                        'cves': [{'cve_id': cve.get('cve_id'), 'severity': cve.get('severity'),
                                  'cvss_score': cve.get('cvss_score'), 'description': cve.get('description', '')[:200]}
                                 for cve in c['cves']]
                    } for c in correlations
                ]
            }
            with open(filename, 'w') as f:
                json.dump(save_data, f, indent=2)
            self.print_status(f"Saved to {filename}", "success")

    # ==================== MENU ====================

    def show_menu(self):
        clear_screen()
        display_banner()

        print(f"{Colors.GREEN}{Colors.BOLD}  OSINT & Reconnaissance{Colors.RESET}")
        print(f"{Colors.DIM}  Open source intelligence gathering{Colors.RESET}")

        # Social-analyzer status
        if self.social_analyzer_available:
            print(f"{Colors.DIM}  social-analyzer: {Colors.GREEN}Available{Colors.RESET}")
        else:
            print(f"{Colors.DIM}  social-analyzer: {Colors.YELLOW}Not installed{Colors.RESET}")

        print(f"{Colors.DIM}  {'─' * 50}{Colors.RESET}")
        print()

        print(f"  {Colors.GREEN}Email{Colors.RESET}")
        print(f"    {Colors.GREEN}[1]{Colors.RESET} Email Lookup")
        print(f"    {Colors.GREEN}[2]{Colors.RESET} Email Permutator")
        print()
        print(f"  {Colors.GREEN}Username{Colors.RESET}")
        print(f"    {Colors.GREEN}[3]{Colors.RESET} Username Lookup")
        print(f"    {Colors.GREEN}[4]{Colors.RESET} Social Analyzer")
        print()
        print(f"  {Colors.GREEN}Phone{Colors.RESET}")
        print(f"    {Colors.GREEN}[5]{Colors.RESET} Phone Number Lookup")
        print()
        print(f"  {Colors.GREEN}Domain/IP{Colors.RESET}")
        print(f"    {Colors.GREEN}[6]{Colors.RESET} Domain Recon")
        print(f"    {Colors.GREEN}[7]{Colors.RESET} IP Address Lookup")
        print(f"    {Colors.GREEN}[8]{Colors.RESET} Subdomain Enum")
        print(f"    {Colors.GREEN}[9]{Colors.RESET} Tech Detection")
        print()
        print(f"  {Colors.MAGENTA}Dossier{Colors.RESET}")
        print(f"    {Colors.MAGENTA}[R]{Colors.RESET} Dossier Manager")
        print()
        print(f"  {Colors.YELLOW}Network{Colors.RESET}")
        print(f"    {Colors.YELLOW}[W]{Colors.RESET} Network Mapper")
        print(f"    {Colors.YELLOW}[H]{Colors.RESET} Web Scanner")
        print(f"    {Colors.YELLOW}[V]{Colors.RESET} Vulnerability Correlator")
        print()
        print(f"  {Colors.CYAN}Tools{Colors.RESET}")
        print(f"    {Colors.CYAN}[G]{Colors.RESET} GEO IP/Domain Lookup")
        print(f"    {Colors.CYAN}[Y]{Colors.RESET} Yandex OSINT")
        print(f"    {Colors.CYAN}[N]{Colors.RESET} Network Test")
        print(f"    {Colors.CYAN}[S]{Colors.RESET} Snoop Database Decoder")
        print(f"    {Colors.CYAN}[D]{Colors.RESET} Sites Database Stats")
        print(f"    {Colors.CYAN}[X]{Colors.RESET} Nmap Scanner")
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
                    self.email_lookup()
                elif choice == "2":
                    self.email_permutator()
                elif choice == "3":
                    self.username_lookup()
                elif choice == "4":
                    username = input(f"\n{Colors.WHITE}Enter username: {Colors.RESET}").strip()
                    if username:
                        self.social_analyzer_search(username)
                elif choice == "5":
                    self.phone_lookup()
                elif choice == "6":
                    self.domain_info()
                elif choice == "7":
                    self.ip_info()
                elif choice == "8":
                    self.subdomain_enum()
                elif choice == "9":
                    self.tech_detect()
                elif choice.lower() == "g":
                    self.run_geoip_module()
                elif choice.lower() == "y":
                    self.run_yandex_module()
                elif choice.lower() == "n":
                    self.run_network_test()
                elif choice.lower() == "s":
                    self.run_snoop_decoder()
                elif choice.lower() == "d":
                    self.show_sites_db_stats()
                elif choice.lower() == "r":
                    self.run_dossier_manager()
                elif choice.lower() == "x":
                    self.nmap_scanner()
                elif choice.lower() == "w":
                    self.network_mapper()
                elif choice.lower() == "h":
                    self.web_scanner()
                elif choice.lower() == "v":
                    self.vuln_correlator()

                if choice in ["1", "2", "3", "4", "5", "6", "7", "8", "9",
                              "g", "y", "n", "G", "Y", "N", "x", "X",
                              "w", "W", "h", "H", "v", "V"]:
                    input(f"\n{Colors.WHITE}Press Enter to continue...{Colors.RESET}")

            except (EOFError, KeyboardInterrupt):
                break


def run():
    Recon().run()


if __name__ == "__main__":
    run()
