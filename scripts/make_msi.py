"""
make_msi.py — Create an MSI installer for AUTARCH using Python's built-in msilib.

Packages the contents of dist/bin/AUTARCH/ (PyInstaller one-dir build) into
a Windows Installer .msi file at dist/bin/AUTARCH-{VERSION}-win64.msi.

Usage:
    python scripts/make_msi.py

Requires:
    - dist/bin/AUTARCH/ to exist (run PyInstaller first)
    - Windows (msilib is Windows-only)
"""

import msilib
import msilib.schema
import msilib.sequence
import msilib.text
import os
import sys
import uuid
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────
SRC_DIR     = Path(__file__).parent.parent
BUNDLE_DIR  = SRC_DIR / 'dist' / 'bin' / 'AUTARCH'
BIN_DIR     = SRC_DIR / 'dist' / 'bin'
VERSION     = '1.3'
APP_NAME    = 'AUTARCH'
MANUFACTURER = 'darkHal Security Group'
PRODUCT_CODE = '{6E4A2B35-C8F1-4D28-A91E-8D4F7C3B2A91}'
UPGRADE_CODE = '{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}'
MSI_OUT     = BIN_DIR / f'AUTARCH-{VERSION}-win64.msi'

# ─────────────────────────────────────────────────────────────────────────────

def make_id(s: str, prefix: str = '') -> str:
    """Create a valid MSI identifier from a string (max 72 chars, no spaces/slashes)."""
    safe = s.replace('\\', '_').replace('/', '_').replace(' ', '_').replace('.', '_').replace('-', '_')
    result = (prefix + safe)[:72]
    if result and result[0].isdigit():
        result = '_' + result[1:]
    return result


def collect_files(bundle_dir: Path):
    """Walk the bundle directory and return (relative_path, abs_path) tuples."""
    items = []
    for path in sorted(bundle_dir.rglob('*')):
        if path.is_file():
            rel = path.relative_to(bundle_dir)
            items.append((rel, path))
    return items


def build_msi():
    if not BUNDLE_DIR.exists():
        print(f"ERROR: Bundle directory not found: {BUNDLE_DIR}")
        print("Run PyInstaller first:  pyinstaller autarch.spec --distpath dist/bin")
        sys.exit(1)

    BIN_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Packaging {BUNDLE_DIR} -> {MSI_OUT}")

    files = collect_files(BUNDLE_DIR)
    print(f"  Files to package: {len(files)}")

    # ── Create the MSI database ───────────────────────────────────────────────
    db = msilib.init_database(
        str(MSI_OUT),
        msilib.schema,
        APP_NAME,
        PRODUCT_CODE,
        VERSION,
        MANUFACTURER,
    )
    msilib.add_tables(db, msilib.sequence)

    # ── Property table (extend — init_database already set some base properties) ──
    # Use the low-level view to INSERT only new properties
    try:
        msilib.add_data(db, 'Property', [
            ('ALLUSERS', '1'),
            ('ARPNOMODIFY', '1'),
        ])
    except Exception:
        pass  # Properties may already exist from init_database; skip

    # ── Directory structure ───────────────────────────────────────────────────
    # Collect all unique subdirectories
    dirs = {}
    dirs['TARGETDIR'] = ('TARGETDIR', 'SourceDir')
    dirs['ProgramFilesFolder'] = ('TARGETDIR', 'PFiles')
    dirs['INSTALLFOLDER'] = ('ProgramFilesFolder', f'{APP_NAME}|{APP_NAME}')

    subdir_set = set()
    for rel, _ in files:
        parts = rel.parts[:-1]  # directory parts (no filename)
        for depth in range(len(parts)):
            sub = '\\'.join(parts[:depth + 1])
            subdir_set.add(sub)

    # Map subdir path → directory ID
    dir_id_map = {'': 'INSTALLFOLDER'}
    dir_rows = [
        ('TARGETDIR', None, 'SourceDir'),
        ('ProgramFilesFolder', 'TARGETDIR', '.'),
        ('INSTALLFOLDER', 'ProgramFilesFolder', APP_NAME),
    ]

    for sub in sorted(subdir_set):
        parts = sub.split('\\')
        parent_path = '\\'.join(parts[:-1])
        parent_id = dir_id_map.get(parent_path, 'INSTALLFOLDER')
        dir_id = make_id(sub, 'dir_')
        dir_id_map[sub] = dir_id
        short_name = parts[-1][:8]  # 8.3 name (simplified)
        long_name = parts[-1]
        dir_name = f'{short_name}|{long_name}' if short_name != long_name else long_name
        dir_rows.append((dir_id, parent_id, dir_name))

    msilib.add_data(db, 'Directory', dir_rows)

    # ── Feature ───────────────────────────────────────────────────────────────
    msilib.add_data(db, 'Feature', [
        ('Main', None, 'AUTARCH Application', 'Complete AUTARCH installation', 1, 1, None, 32),
    ])

    # ── Components and files ──────────────────────────────────────────────────
    comp_rows  = []
    file_rows  = []
    feat_comp  = []

    for idx, (rel, abs_path) in enumerate(files):
        parts      = rel.parts
        subdir_key = '\\'.join(parts[:-1])
        dir_id     = dir_id_map.get(subdir_key, 'INSTALLFOLDER')
        comp_id    = f'c{idx}'
        file_id    = f'f{idx}'
        comp_guid  = str(uuid.uuid5(uuid.UUID(UPGRADE_CODE), str(rel))).upper()
        comp_guid  = '{' + comp_guid + '}'

        # Component row: (Component, ComponentId, Directory_, Attributes, Condition, KeyPath)
        comp_rows.append((comp_id, comp_guid, dir_id, 0, None, file_id))

        # File row: (File, Component_, FileName, FileSize, Version, Language, Attributes, Sequence)
        fname = parts[-1]
        short = fname[:8]
        long  = fname
        file_name = f'{short}|{long}' if short != long else long
        file_size = abs_path.stat().st_size
        file_rows.append((file_id, comp_id, file_name, file_size, None, None, 512, idx + 1))

        # FeatureComponents: (Feature_, Component_)
        feat_comp.append(('Main', comp_id))

    msilib.add_data(db, 'Component',        comp_rows)
    msilib.add_data(db, 'File',             file_rows)
    msilib.add_data(db, 'FeatureComponents', feat_comp)

    # ── Media / cabinet ──────────────────────────────────────────────────────
    # CAB.commit() embeds the cabinet, adds the Media row, and calls db.Commit()
    cab = msilib.CAB('autarch.cab')
    for idx, (rel, abs_path) in enumerate(files):
        # append(full_path, file_id, logical_name_in_cab)
        cab.append(str(abs_path), f'f{idx}', rel.name)

    cab.commit(db)  # handles Media table insert + db.Commit() internally

    size_mb = round(MSI_OUT.stat().st_size / (1024 * 1024), 1)
    print(f"\n  OK: MSI created: {MSI_OUT}  ({size_mb} MB)")


if __name__ == '__main__':
    build_msi()
