#!/usr/bin/env python3
"""
windows_installer_monitor.py

Single-file utility to monitor what files and processes an installer (.exe) creates or modifies.

Features:
- Snapshot mode: take 'before' and 'after' filesystem snapshots and compare them.
- Live mode: launch the installer and monitor filesystem events (watchdog) for given paths and record process tree (psutil).
- Saves results as JSON and CSV in output directory.

Limitations:
- Needs to be run on Windows with administrator privileges for system-wide paths.
- Cannot replace Procmon/ETW for low-level kernel/driver operations; this is higher-level and best-effort.

Dependencies:
- psutil
- watchdog

Install: pip install psutil watchdog

Usage examples:
# snapshot mode (recommended inside a VM/sandbox)
python windows_installer_monitor.py snapshot --before before.json --after after.json --out results

# snapshot convenience (script runs installer and snapshots around it)
python windows_installer_monitor.py run-and-snapshot --installer "C:\\path\\to\\setup.exe" --out results

# live monitor (watch paths while running installer)
python windows_installer_monitor.py live --installer "C:\\path\\to\\setup.exe" --watch "C:\\Program Files" "C:\\Users\\" --out results

"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

try:
    import psutil
except Exception:
    psutil = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    Observer = None
    FileSystemEventHandler = object


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

def snapshot_files(paths, follow_links=False, path_pattern=None):
    """Return a dict mapping relative path -> {size, mtime} for given root paths.
    Note: for big trees this can be slow. Caller may choose narrower paths.
    """
    normalized_pattern = path_pattern.lower() if path_pattern else None
    out = {}
    for root in paths:
        if not os.path.exists(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
            for fname in filenames:
                full = os.path.join(dirpath, fname)
                if normalized_pattern and normalized_pattern not in full.lower():
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


# ---------- Live filesystem monitor using watchdog ----------

class RecordingEventHandler(FileSystemEventHandler):
    def __init__(self):
        self.events = []

    def on_any_event(self, event):
        ts = datetime.utcnow().isoformat() + 'Z'
        rec = {
            'timestamp': ts,
            'event_type': event.event_type,
            'is_directory': event.is_directory,
            'src_path': getattr(event, 'src_path', None),
            'dest_path': getattr(event, 'dest_path', None),
        }
        self.events.append(rec)


def start_watch(paths, handler, recursive=True):
    if Observer is None:
        raise RuntimeError('watchdog not installed')
    obs = Observer()
    for p in paths:
        if os.path.exists(p):
            obs.schedule(handler, p, recursive=recursive)
    obs.start()
    return obs


# ---------- Process monitoring helpers ----------

class ProcMonitor(threading.Thread):
    def __init__(self, root_pid=None, poll_interval=0.5):
        super().__init__()
        self.root_pid = root_pid
        self.poll_interval = poll_interval
        self.running = True
        self.records = []

    def run(self):
        if psutil is None:
            raise RuntimeError('psutil not available')
        while self.running:
            now = datetime.utcnow().isoformat() + 'Z'
            try:
                procs = []
                if self.root_pid and psutil.pid_exists(self.root_pid):
                    try:
                        root = psutil.Process(self.root_pid)
                        # gather tree
                        proc_list = [root] + root.children(recursive=True)
                    except Exception:
                        proc_list = []
                else:
                    proc_list = psutil.process_iter()
                for p in proc_list:
                    try:
                        proc = p if isinstance(p, psutil.Process) else psutil.Process(p.pid)
                        procs.append({'pid': proc.pid, 'ppid': proc.ppid(), 'name': proc.name(), 'exe': proc.exe(), 'cmdline': proc.cmdline(), 'username': proc.username()})
                    except Exception:
                        continue
                self.records.append({'timestamp': now, 'snapshot': procs})
            except Exception as e:
                self.records.append({'timestamp': now, 'error': str(e)})
            time.sleep(self.poll_interval)

    def stop(self):
        self.running = False
        self.join(timeout=2)


# ---------- Utilities ----------

def save_json(obj, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def timestamp():
    return datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')


# ---------- High-level flows ----------


def run_and_snapshot(installer, outdir, paths_to_snapshot=None, wait=5, path_pattern=None):
    ensure_windows()
    if paths_to_snapshot is None:
        paths_to_snapshot = DEFAULT_WATCH_PATHS
    before_files = snapshot_files(paths_to_snapshot, path_pattern=path_pattern)

    # run installer
    print('Launching installer:', installer)
    p = subprocess.Popen(installer, shell=False)
    p.wait()
    print('Installer finished, waiting {}s for final writes...'.format(wait))
    time.sleep(wait)

    after_files = snapshot_files(paths_to_snapshot, path_pattern=path_pattern)

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


def live_monitor(installer, watch_paths, outdir, poll_interval=0.7):
    ensure_windows()
    handler = RecordingEventHandler()
    obs = start_watch(watch_paths, handler, recursive=True)

    proc = None
    procmon = None
    try:
        print('Launching installer:', installer)
        proc = subprocess.Popen(installer, shell=False)
        # start process monitor attaching to installer PID
        procmon = ProcMonitor(root_pid=proc.pid, poll_interval=poll_interval)
        procmon.start()
        # wait for process to finish
        proc.wait()
        print('Installer finished, waiting 2s for final events...')
        time.sleep(2)
    finally:
        if procmon:
            procmon.stop()
        obs.stop()
        obs.join(timeout=2)

    results = {
        'meta': {'installer': installer, 'timestamp': timestamp(), 'watch_paths': watch_paths},
        'fs_events': handler.events,
        'process_snapshots': procmon.records if procmon else [],
    }
    outpath = os.path.join(outdir, f'live_results_{timestamp()}.json')
    save_json(results, outpath)
    print('Saved live results to', outpath)
    return results


# ---------- Command-line interface ----------


def main():
    parser = argparse.ArgumentParser(description='Monitor installer file/registry changes (Windows)')
    sub = parser.add_subparsers(dest='cmd')

    p_snap = sub.add_parser('snapshot', help='Compare two snapshot JSON files')
    p_snap.add_argument('--before', required=True)
    p_snap.add_argument('--after', required=True)
    p_snap.add_argument('--out', required=True)

    p_run = sub.add_parser('run-and-snapshot', help='Run an installer and snapshot around it')
    p_run.add_argument('--installer', required=True)
    p_run.add_argument('--out', required=True)
    p_run.add_argument('--paths', nargs='*', default=DEFAULT_WATCH_PATHS)
    p_run.add_argument('--wait', type=int, default=5)
    p_run.add_argument('--path-pattern', help='Only include files whose path contains this pattern (case-insensitive)')

    p_live = sub.add_parser('live', help='Live monitor file events while running installer')
    p_live.add_argument('--installer', required=True)
    p_live.add_argument('--out', required=True)
    p_live.add_argument('--watch', nargs='*', default=DEFAULT_WATCH_PATHS)
    p_live.add_argument('--interval', type=float, default=0.7)

    args = parser.parse_args()

    if args.cmd == 'snapshot':
        # load two snapshots and compare
        with open(args.before, 'r', encoding='utf-8') as f:
            b = json.load(f)
        with open(args.after, 'r', encoding='utf-8') as f:
            a = json.load(f)
        # expecting snapshots to be simple dicts of path->meta
        added, removed, changed = compare_file_snapshots(b, a)
        added, removed, changed = sanitize_results(added, removed, changed)
        results = {'added': added, 'removed': removed, 'changed': changed}
        os.makedirs(args.out, exist_ok=True)
        save_json(results, os.path.join(args.out, f'compare_{timestamp()}.json'))
        print('Comparison saved to', args.out)
        return

    if args.cmd == 'run-and-snapshot':
        os.makedirs(args.out, exist_ok=True)
        res = run_and_snapshot(
            args.installer,
            args.out,
            paths_to_snapshot=args.paths,
            wait=args.wait,
            path_pattern=args.path_pattern,
        )
        return

    if args.cmd == 'live':
        os.makedirs(args.out, exist_ok=True)
        res = live_monitor(args.installer, args.watch, args.out, poll_interval=args.interval)
        return

    parser.print_help()


if __name__ == '__main__':
    main()
