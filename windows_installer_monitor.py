#!/usr/bin/env python3
"""
windows_installer_monitor.py

Single-file utility to run an installer (.exe), capture filesystem state before/after and list what changed.

Fonctionnalités:
- Exécute automatiquement l’installeur puis compare les chemins surveillés.
- Filtre optionnel sur un motif (`--path-pattern`) pour ne garder que certains fichiers.
- Calcule le SHA-256 pour chaque fichier retenu et enregistre le résultat en JSON.

Limitations:
- Needs to be run on Windows with administrator privileges for system-wide paths.
- Cannot replace Procmon/ETW for low-level kernel/driver operations; this is higher-level and best-effort.

Dependencies:
- Un environnement Python 3.8+

Usage:
python windows_installer_monitor.py run-and-snapshot --installer "C:\\path\\to\\setup.exe" --out results

"""
import argparse
import fnmatch
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime

DEFAULT_WATCH_PATHS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Users", 
]


def ensure_windows():
    if platform.system() != 'Windows':
        print('This script is intended to run on Windows. Exiting.')
        sys.exit(1)


# ---------- Filesystem snapshot helpers ----------

def snapshot_files(paths, follow_links=False, path_pattern=None, extensions=None):
    """Return a dict mapping relative path -> {size, mtime} for given root paths.
    Note: for big trees this can be slow. Caller may choose narrower paths.
    """
    normalized_pattern = path_pattern.lower() if path_pattern else None
    normalized_exts = [ext.lower() for ext in extensions] if extensions else None
    out = {}
    for root in paths:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                full_lower = full.lower()
                if normalized_pattern and normalized_pattern not in full_lower:
                    continue
                if normalized_exts and not any(fnmatch.fnmatch(full_lower, pattern) for pattern in normalized_exts):
                    continue
                try:
                    st = os.stat(full)
                    meta = {'size': st.st_size, 'mtime': st.st_mtime}
                    sha = file_sha256(full)
                    if sha:
                        meta['sha256'] = sha
                    out[full] = meta
                except Exception:
                    # skip files we can't stat (permissions, locked files)
                    continue
    return out


def normalize_extension_patterns(value):
    if not value:
        return None
    if isinstance(value, str):
        raw = value.split(',')
    else:
        raw = []
        for item in value:
            raw.extend(item.split(','))
    patterns = []
    for item in raw:
        pattern = item.strip()
        if not pattern:
            continue
        if pattern.startswith('.'):
            pattern = f'*{pattern}'
        patterns.append(pattern.lower())
    return patterns or None


def file_sha256(path, chunk_size=1024 * 1024):
    """Return SHA256 hex digest for path or None if not readable."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(chunk_size), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def compare_file_snapshots(before, after):
    added = {}
    removed = {}
    changed = {}
    for p, meta in after.items():
        if p not in before:
            added[p] = meta
        else:
            b = before[p]
            if files_differ(b, meta):
                changed[p] = {'before': b, 'after': meta}
    for p, meta in before.items():
        if p not in after:
            removed[p] = meta
    return added, removed, changed


def files_differ(before_meta, after_meta):
    if before_meta.get('size') != after_meta.get('size'):
        return True
    if int(before_meta.get('mtime', 0)) != int(after_meta.get('mtime', 0)):
        return True
    if before_meta.get('sha256') != after_meta.get('sha256'):
        return True
    return False


def sanitize_meta(meta):
    if not isinstance(meta, dict):
        return meta
    clean = dict(meta)
    clean.pop('size', None)
    clean.pop('mtime', None)
    return clean


def sanitize_results(added, removed, changed):
    clean_added = {p: sanitize_meta(meta) for p, meta in added.items()}
    clean_removed = {p: sanitize_meta(meta) for p, meta in removed.items()}
    clean_changed = {}
    for p, payload in changed.items():
        clean_changed[p] = {
            'before': sanitize_meta(payload.get('before')),
            'after': sanitize_meta(payload.get('after')),
        }
    return clean_added, clean_removed, clean_changed


# ---------- Utilities ----------

def save_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def timestamp():
    return datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')


# ---------- High-level flows ----------


def run_and_snapshot(installer, outdir, paths_to_snapshot=None, wait=5, path_pattern=None, extensions=None):
    ensure_windows()
    if paths_to_snapshot is None:
        paths_to_snapshot = DEFAULT_WATCH_PATHS
    before_files = snapshot_files(
        paths_to_snapshot,
        path_pattern=path_pattern,
        extensions=extensions,
    )

    # run installer
    print('Launching installer:', installer)
    p = subprocess.Popen(installer, shell=False)
    p.wait()
    print('Installer finished, waiting {}s for final writes...'.format(wait))
    time.sleep(wait)

    after_files = snapshot_files(
        paths_to_snapshot,
        path_pattern=path_pattern,
        extensions=extensions,
    )

    added, removed, changed = compare_file_snapshots(before_files, after_files)
    added, removed, changed = sanitize_results(added, removed, changed)

    results = {
        'meta': {'installer': installer, 'timestamp': timestamp()},
        'files': {'added': added, 'removed': removed, 'changed': changed},
    }
    outpath = os.path.join(outdir, f'results_{timestamp()}.json')
    save_json(results, outpath)
    print('Saved results to', outpath)
    return results


# ---------- Command-line interface ----------


def main():
    parser = argparse.ArgumentParser(description='Run an installer and diff filesystem changes (Windows)')
    sub = parser.add_subparsers(dest='cmd')

    p_run = sub.add_parser('run-and-snapshot', help='Run an installer and snapshot around it')
    p_run.add_argument('--installer', required=True)
    p_run.add_argument('--out', required=True)
    p_run.add_argument('--paths', nargs='*', default=DEFAULT_WATCH_PATHS)
    p_run.add_argument('--wait', type=int, default=5)
    p_run.add_argument('--path-pattern', help='Only include files whose path contains this pattern (case-insensitive)')
    p_run.add_argument('--extensions', help='Comma-separated glob patterns to include (e.g., "*.exe,*.txt")')

    args = parser.parse_args()

    if args.cmd == 'run-and-snapshot':
        os.makedirs(args.out, exist_ok=True)
        run_and_snapshot(
            args.installer,
            args.out,
            paths_to_snapshot=args.paths,
            wait=args.wait,
            path_pattern=args.path_pattern,
            extensions=normalize_extension_patterns(args.extensions),
        )
        return

    parser.print_help()


if __name__ == '__main__':
    main()
