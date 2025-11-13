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
from datetime import datetime, timezone

DEFAULT_WATCH_PATHS = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Users",
]

ENV_PATH_PLACEHOLDER_VARS = [
    'USERPROFILE',
    'HOMEDRIVE',
    'HOMEPATH',
    'LOCALAPPDATA',
    'APPDATA',
    'PROGRAMDATA',
    'PROGRAMFILES',
    'PROGRAMFILES(X86)',
    'COMMONPROGRAMFILES',
    'COMMONPROGRAMFILES(X86)',
]


def ensure_windows():
    if platform.system() != 'Windows':
        print('This script is intended to run on Windows. Exiting.')
        sys.exit(1)


# ---------- Filesystem snapshot helpers ----------

def debug_print(enabled, message):
    if enabled:
        print(f'[verbose] {message}')


def snapshot_files(paths, follow_links=False, path_pattern=None, extensions=None, exclude_extensions=None, verbose=False):
    """Return a dict mapping relative path -> {size, mtime} for given root paths.
    Note: for big trees this can be slow. Caller may choose narrower paths.
    """
    normalized_pattern = path_pattern.lower() if path_pattern else None
    normalized_exts = [ext.lower() for ext in extensions] if extensions else None
    normalized_exclude_exts = [ext.lower() for ext in exclude_extensions] if exclude_extensions else None
    out = {}
    total_files = 0
    retained_files = 0
    for root in paths:
        if not os.path.exists(root):
            debug_print(verbose, f'Skipping missing root: {root}')
            continue
        debug_print(verbose, f'Scanning root: {root}')
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                full_lower = full.lower()
                total_files += 1
                if normalized_pattern and normalized_pattern not in full_lower:
                    continue
                if normalized_exclude_exts and any(fnmatch.fnmatch(full_lower, pattern) for pattern in normalized_exclude_exts):
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
                    retained_files += 1
                except Exception:
                    # skip files we can't stat (permissions, locked files)
                    continue
    debug_print(verbose, f'Snapshot complete: retained {retained_files} files out of {total_files} inspected')
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


def build_env_path_mappings():
    """Return list of (norm_value, raw_value, placeholder) sorted by length."""
    mappings = []
    seen = set()
    for var in ENV_PATH_PLACEHOLDER_VARS:
        raw_value = os.environ.get(var)
        if not raw_value:
            continue
        raw_value = raw_value.replace('/', '\\').rstrip('\\/')
        if not raw_value:
            continue
        norm_value = raw_value.lower()
        if norm_value in seen:
            continue
        seen.add(norm_value)
        mappings.append((norm_value, raw_value, f'%{var}%'))
    mappings.sort(key=lambda item: len(item[0]), reverse=True)
    return mappings


def replace_path_with_env_placeholder(path, mappings=None):
    if not path:
        return path
    if mappings is None:
        mappings = build_env_path_mappings()
    normalized = path.replace('/', '\\')
    lowered = normalized.lower()
    for norm_value, raw_value, placeholder in mappings:
        if lowered.startswith(norm_value):
            suffix = normalized[len(raw_value):].lstrip('\\/')
            return placeholder if not suffix else f'{placeholder}\\{suffix}'
    return normalized


def apply_env_placeholders_to_results(added, removed, changed):
    mappings = build_env_path_mappings()

    def remap(mapping):
        return {replace_path_with_env_placeholder(p, mappings): meta for p, meta in mapping.items()}

    return remap(added), remap(removed), remap(changed)


# ---------- Utilities ----------

def save_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def timestamp():
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


# ---------- High-level flows ----------


def run_and_snapshot(installer, outdir, paths_to_snapshot=None, wait=5, path_pattern=None, extensions=None, exclude_extensions=None, env_placeholders=False, verbose=False):
    ensure_windows()
    if paths_to_snapshot is None:
        paths_to_snapshot = DEFAULT_WATCH_PATHS
    before_files = snapshot_files(
        paths_to_snapshot,
        path_pattern=path_pattern,
        extensions=extensions,
        exclude_extensions=exclude_extensions,
        verbose=verbose,
    )

    # run installer
    print('Launching installer:', installer)
    debug_print(verbose, f'Watching paths: {paths_to_snapshot}')
    p = subprocess.Popen(installer, shell=False)
    p.wait()
    print('Installer finished, waiting {}s for final writes...'.format(wait))
    time.sleep(wait)

    after_files = snapshot_files(
        paths_to_snapshot,
        path_pattern=path_pattern,
        extensions=extensions,
        exclude_extensions=exclude_extensions,
        verbose=verbose,
    )

    added, removed, changed = compare_file_snapshots(before_files, after_files)
    added, removed, changed = sanitize_results(added, removed, changed)
    if env_placeholders:
        added, removed, changed = apply_env_placeholders_to_results(added, removed, changed)

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
    p_run.add_argument('--extensions-exclude', help='Comma-separated glob patterns to exclude (e.g., "*.lnk,*.tmp")')
    p_run.add_argument('--env-placeholders', action='store_true', help='Replace known path prefixes with %%ENV%% placeholders in the JSON output')
    p_run.add_argument('--verbose', action='store_true', help='Print detailed progress information')

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
            exclude_extensions=normalize_extension_patterns(args.extensions_exclude),
            env_placeholders=args.env_placeholders,
            verbose=args.verbose,
        )
        return

    parser.print_help()


if __name__ == '__main__':
    main()
