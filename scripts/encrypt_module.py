#!/usr/bin/env python3
"""
encrypt_module.py — Encrypt a Python module into AUTARCH .aes format.

Usage:
    python scripts/encrypt_module.py <source.py> [output.aes] [--password P] [--name N]

Examples:
    python scripts/encrypt_module.py modules/encmod_sources/floppy_dick.py
    python scripts/encrypt_module.py mymod.py modules/encrypted/mymod.aes --password s3cr3t
    python scripts/encrypt_module.py mymod.py --password s3cr3t --name "My Module" --version 1.1
"""

import argparse
import getpass
import json
import sys
from pathlib import Path

SRC_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(SRC_DIR))


def main():
    parser = argparse.ArgumentParser(description='Encrypt a Python module to AUTARCH .aes format')
    parser.add_argument('source',          help='Path to the source .py file')
    parser.add_argument('output', nargs='?', help='Output .aes path (default: modules/encrypted/<stem>.aes)')
    parser.add_argument('--password', '-p', default='', help='Encryption password (prompted if omitted)')
    parser.add_argument('--name',           default='', help='Display name for the module')
    parser.add_argument('--version',        default='1.0', help='Module version (default: 1.0)')
    parser.add_argument('--author',         default='', help='Module author')
    parser.add_argument('--description',    default='', help='Module description')
    parser.add_argument('--tags',           default='', help='Comma-separated tags')
    args = parser.parse_args()

    src = Path(args.source)
    if not src.exists():
        print(f"ERROR: Source file not found: {src}", file=sys.stderr)
        sys.exit(1)

    # Determine output path
    if args.output:
        out = Path(args.output)
    else:
        enc_dir = SRC_DIR / 'modules' / 'encrypted'
        enc_dir.mkdir(parents=True, exist_ok=True)
        out = enc_dir / (src.stem + '.aes')

    # Get password
    password = args.password
    if not password:
        password = getpass.getpass(f"Encryption password for {src.name}: ")
        confirm  = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("ERROR: Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    if not password:
        print("ERROR: Password cannot be empty.", file=sys.stderr)
        sys.exit(1)

    # Build metadata
    tags = [t.strip() for t in args.tags.split(',') if t.strip()]
    metadata = {
        'name':        args.name or src.stem.replace('_', ' ').title(),
        'version':     args.version,
        'author':      args.author,
        'description': args.description,
        'tags':        tags,
        'source':      src.name,
    }

    # Encrypt
    from core.module_crypto import encrypt_file
    encrypt_file(src, out, password, metadata)

    size_kb = round(out.stat().st_size / 1024, 1)
    print(f"  Encrypted: {src.name} -> {out}  ({size_kb} KB)")
    print(f"  Name:      {metadata['name']}")
    print(f"  Version:   {metadata['version']}")
    print(f"  Tags:      {', '.join(tags) or '(none)'}")
    print()
    print("  Copy the .aes file to modules/encrypted/ and it will appear in the web UI.")


if __name__ == '__main__':
    main()
