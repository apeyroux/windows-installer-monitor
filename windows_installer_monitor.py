#!/usr/bin/env python3
"""Surveillance d'installateur Windows et comparaison d'instantanés.

Le script se charge d'exécuter un installeur ``.exe`` puis de comparer l'état du
système de fichiers avant et après l'opération. Il enregistre les différences
dans un rapport JSON en option.

Fonctionnalités principales
---------------------------
* Exécution automatique de l'installeur et capture des chemins surveillés.
* Filtrage facultatif (`--path-pattern`, `--extensions`, `--extensions-exclude`).
* Calcul de l'empreinte SHA-256 pour chaque fichier conservé.

Limitations
-----------
* L'outil doit être exécuté sous Windows avec les privilèges nécessaires.
* Il ne remplace pas Procmon/ETW pour l'observation bas niveau du noyau.

Utilisation rapide
------------------
``python windows_installer_monitor.py run-and-snapshot --installer "C:\\path\\to\\setup.exe" --out results``
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
from collections.abc import Mapping as MappingABC
from datetime import datetime, timezone
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypedDict,
    Union,
    cast,
)


class FileMetadata(TypedDict, total=False):
    """Structure minimale pour décrire un fichier suivi."""

    size: int
    mtime: float
    sha256: str


class ChangedFileEntry(TypedDict, total=False):
    """Représente l'état d'un fichier avant et après installation."""

    before: FileMetadata
    after: FileMetadata


# Ces alias rendent les annotations plus lisibles dans les signatures publiques.
Snapshot = Dict[str, FileMetadata]
ChangedSnapshot = Dict[str, ChangedFileEntry]

MIN_SUPPORTED_PYTHON: Tuple[int, int] = (3, 10)


def ensure_supported_python() -> None:
    """Vérifie que l'interpréteur courant correspond à la version minimale requise."""

    if sys.version_info < MIN_SUPPORTED_PYTHON:
        current = '.'.join(str(part) for part in sys.version_info[:3])
        required = f"{MIN_SUPPORTED_PYTHON[0]}.{MIN_SUPPORTED_PYTHON[1]}"
        print(
            'Ce script nécessite Python {required} ou plus récent. '
            'Version détectée: {current}.'
            .format(required=required, current=current)
        )
        sys.exit(1)


DEFAULT_WATCH_PATHS: List[str] = [
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\Users",
]

ENV_PATH_PLACEHOLDER_VARS: List[str] = [
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


def ensure_windows() -> None:
    """Interrompt l'exécution si le script n'est pas lancé sur Windows."""

    if platform.system() != 'Windows':
        print('This script is intended to run on Windows. Exiting.')
        sys.exit(1)


# ---------- Filesystem snapshot helpers ----------

def debug_print(enabled: bool, message: str) -> None:
    """Affiche un message de diagnostic lorsque le mode verbeux est activé."""

    if enabled:
        print(f'[verbose] {message}')


def snapshot_files(
    paths: Sequence[str],
    follow_links: bool = False,
    path_pattern: Optional[str] = None,
    extensions: Optional[Sequence[str]] = None,
    exclude_extensions: Optional[Sequence[str]] = None,
    verbose: bool = False,
) -> Snapshot:
    """Représente l'état des fichiers sous plusieurs chemins racines.

    Chaque fichier retenu est indexé par son chemin absolu et associé à un
    dictionnaire contenant les métadonnées utiles (taille, date de modification
    et empreinte SHA-256 si possible). Les filtres permettent de limiter le
    périmètre et d'accélérer le traitement.
    """

    normalized_pattern = path_pattern.lower() if path_pattern else None
    normalized_exts = [ext.lower() for ext in extensions] if extensions else None
    normalized_exclude_exts = [ext.lower() for ext in exclude_extensions] if exclude_extensions else None
    out: Snapshot = {}
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
                    # Les métadonnées minimales sont la taille et la date de
                    # dernière modification. Elles permettent d'identifier les
                    # changements même sans hachage.
                    meta: FileMetadata = {'size': st.st_size, 'mtime': st.st_mtime}
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


def normalize_extension_patterns(
    value: Optional[Union[str, Iterable[str]]]
) -> Optional[List[str]]:
    """Nettoie et unifie la liste de motifs d'extension fournis en argument."""

    if not value:
        return None
    if isinstance(value, str):
        raw = value.split(',')
    else:
        raw_list: List[str] = []
        for item in value:
            raw_list.extend(item.split(','))
        raw = raw_list
    patterns: List[str] = []
    for item in raw:
        pattern = item.strip()
        if not pattern:
            continue
        if pattern.startswith('.'):
            pattern = f'*{pattern}'
        patterns.append(pattern.lower())
    return patterns or None


def file_sha256(path: str, chunk_size: int = 1024 * 1024) -> Optional[str]:
    """Calcule l'empreinte SHA-256 d'un fichier en limitant l'usage mémoire."""
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as fh:
            for chunk in iter(lambda: fh.read(chunk_size), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def compare_file_snapshots(
    before: Mapping[str, FileMetadata],
    after: Mapping[str, FileMetadata],
) -> Tuple[Snapshot, Snapshot, ChangedSnapshot]:
    """Compare deux instantanés et retourne les fichiers ajoutés, supprimés et modifiés."""

    added: Snapshot = {}
    removed: Snapshot = {}
    changed: ChangedSnapshot = {}
    for p, meta in after.items():
        if p not in before:
            added[p] = meta
        else:
            b = before[p]
            if files_differ(b, meta):
                changed[p] = {
                    'before': ensure_file_metadata(b),
                    'after': ensure_file_metadata(meta),
                }
    for p, meta in before.items():
        if p not in after:
            removed[p] = meta
    return added, removed, changed


def files_differ(before_meta: Mapping[str, Any], after_meta: Mapping[str, Any]) -> bool:
    """Détermine si deux ensembles de métadonnées décrivent un fichier différent."""

    if before_meta.get('size') != after_meta.get('size'):
        return True
    if int(before_meta.get('mtime', 0)) != int(after_meta.get('mtime', 0)):
        return True
    if before_meta.get('sha256') != after_meta.get('sha256'):
        return True
    return False


def sanitize_meta(meta: Mapping[str, Any]) -> FileMetadata:
    """Supprime les informations volatiles d'un dictionnaire de métadonnées."""

    clean: FileMetadata = {}
    if not isinstance(meta, MappingABC):
        return clean
    if 'sha256' in meta:
        clean['sha256'] = meta['sha256']
    return clean


def ensure_file_metadata(meta: object) -> FileMetadata:
    """Garantit un dictionnaire typé même si l'entrée est partielle ou invalide."""

    if isinstance(meta, MappingABC):
        return cast(FileMetadata, dict(meta))
    return cast(FileMetadata, {})


def sanitize_results(
    added: Mapping[str, FileMetadata],
    removed: Mapping[str, FileMetadata],
    changed: Mapping[str, ChangedFileEntry],
) -> Tuple[Snapshot, Snapshot, ChangedSnapshot]:
    """Filtre les métadonnées pour ne conserver que les informations utiles."""

    clean_added: Snapshot = {p: sanitize_meta(meta) for p, meta in added.items()}
    clean_removed: Snapshot = {p: sanitize_meta(meta) for p, meta in removed.items()}
    clean_changed: ChangedSnapshot = {}
    for p, payload in changed.items():
        if isinstance(payload, MappingABC):
            before_meta = ensure_file_metadata(payload.get('before'))
            after_meta = ensure_file_metadata(payload.get('after'))
        else:
            before_meta = ensure_file_metadata(None)
            after_meta = ensure_file_metadata(None)
        clean_changed[p] = {
            'before': sanitize_meta(before_meta),
            'after': sanitize_meta(after_meta),
        }
    return clean_added, clean_removed, clean_changed


def build_env_path_mappings() -> List[Tuple[str, str, str]]:
    """Construit une liste de couples chemin/placeholder triés par longueur."""

    mappings: List[Tuple[str, str, str]] = []
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


def replace_path_with_env_placeholder(
    path: str, mappings: Optional[Sequence[Tuple[str, str, str]]] = None
) -> str:
    """Remplace un préfixe de chemin par son placeholder d'environnement."""

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


def apply_env_placeholders_to_results(
    added: Mapping[str, FileMetadata],
    removed: Mapping[str, FileMetadata],
    changed: Mapping[str, ChangedFileEntry],
) -> Tuple[Snapshot, Snapshot, ChangedSnapshot]:
    """Applique les placeholders d'environnement aux chemins d'un rapport."""

    mappings = build_env_path_mappings()

    def remap_snapshot(mapping: Mapping[str, FileMetadata]) -> Snapshot:
        return {
            replace_path_with_env_placeholder(p, mappings): ensure_file_metadata(meta)
            for p, meta in mapping.items()
        }

    def remap_changed(mapping: Mapping[str, ChangedFileEntry]) -> ChangedSnapshot:
        remapped: ChangedSnapshot = {}
        for path, meta in mapping.items():
            if isinstance(meta, MappingABC):
                before_meta = ensure_file_metadata(meta.get('before'))
                after_meta = ensure_file_metadata(meta.get('after'))
            else:
                before_meta = ensure_file_metadata(None)
                after_meta = ensure_file_metadata(None)
            remapped[replace_path_with_env_placeholder(path, mappings)] = {
                'before': before_meta,
                'after': after_meta,
            }
        return remapped

    return remap_snapshot(added), remap_snapshot(removed), remap_changed(changed)


def expand_env_placeholders(
    path: str, mappings: Optional[Sequence[Tuple[str, str, str]]] = None
) -> str:
    """Remplace un placeholder d'environnement par sa valeur réelle."""

    if not path:
        return path
    if mappings is None:
        mappings = build_env_path_mappings()
    placeholder_map = {placeholder.lower(): raw_value for _, raw_value, placeholder in mappings}
    normalized = path.replace('/', '\\')
    lowered = normalized.lower()
    for placeholder, raw_value in placeholder_map.items():
        if lowered.startswith(placeholder):
            suffix = normalized[len(placeholder):].lstrip('\\/')
            return raw_value if not suffix else f'{raw_value}\\{suffix}'
    return normalized


# ---------- Utilities ----------

def save_json(obj: Mapping[str, Any], path: str) -> None:
    """Enregistre l'objet JSON dans le chemin fourni en créant les dossiers."""

    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def timestamp() -> str:
    """Retourne un horodatage UTC compact (format YYYYMMDDThhmmssZ)."""

    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


# ---------- High-level flows ----------


def run_and_snapshot(
    installer: str,
    outdir: str,
    paths_to_snapshot: Optional[Sequence[str]] = None,
    wait: int = 5,
    path_pattern: Optional[str] = None,
    extensions: Optional[Sequence[str]] = None,
    exclude_extensions: Optional[Sequence[str]] = None,
    env_placeholders: bool = False,
    verbose: bool = False,
    out_filename: Optional[str] = None,
) -> Mapping[str, object]:
    """Exécute l'installeur et capture l'état du système avant/après."""

    ensure_supported_python()
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

    now_str = timestamp()
    results: Dict[str, object] = {
        'meta': {'installer': installer, 'timestamp': now_str},
        'files': {'added': added, 'removed': removed, 'changed': changed},
    }
    if out_filename:
        outpath = out_filename if os.path.isabs(out_filename) else os.path.join(outdir, out_filename)
    else:
        outpath = os.path.join(outdir, f'results_{now_str}.json')
    save_json(results, outpath)
    print('Saved results to', outpath)
    return results


def check_report(report_path: str, verbose: bool = False) -> int:
    """Valide un rapport JSON en recalculant les empreintes SHA-256."""

    ensure_supported_python()
    ensure_windows()
    if not os.path.exists(report_path):
        print('Report not found:', report_path)
        return 1

    with open(report_path, 'r', encoding='utf-8') as fh:
        report = json.load(fh)

    files_section = report.get('files', {})
    mappings = build_env_path_mappings()

    total = 0
    ok = 0
    missing = []
    mismatched = []
    skipped = []

    def add_entry(path, meta, category):
        nonlocal total, ok
        if not isinstance(meta, dict):
            skipped.append((path, category, 'missing meta dict'))
            return
        sha = meta.get('sha256')
        if not sha:
            skipped.append((path, category, 'no sha256 recorded'))
            return
        total += 1
        real_path = expand_env_placeholders(path, mappings)
        debug_print(verbose, f'Checking {category} file: {path} -> {real_path}')
        if not os.path.exists(real_path):
            missing.append((path, real_path, category))
            return
        actual_sha = file_sha256(real_path)
        if actual_sha == sha:
            ok += 1
            debug_print(verbose, f'OK: {real_path}')
        else:
            mismatched.append((path, real_path, category, sha, actual_sha))

    for category in ('added',):
        for path, meta in files_section.get(category, {}).items():
            add_entry(path, meta, category)

    for path, payload in files_section.get('changed', {}).items():
        after_meta = (payload or {}).get('after')
        add_entry(path, after_meta or {}, 'changed.after')

    print(f'Checked {total} files: {ok} OK, {len(mismatched)} mismatched, {len(missing)} missing, {len(skipped)} skipped.')

    if missing:
        print('Missing files:')
        for path, real_path, category in missing:
            print(f' - {category}: {path} -> {real_path} (not found)')

    if mismatched:
        print('SHA mismatches:')
        for path, real_path, category, expected, actual in mismatched:
            print(f' - {category}: {path} -> {real_path}')
            print(f'   expected {expected}')
            print(f"   actual   {actual or '<unreadable>'}")

    if skipped:
        debug_print(verbose, f'Skipped entries: {len(skipped)}')

    return 0 if not mismatched and not missing else 2


# ---------- Command-line interface ----------


def main():
    ensure_supported_python()
    parser = argparse.ArgumentParser(description='Run an installer and diff filesystem changes (Windows)')
    sub = parser.add_subparsers(dest='cmd')

    p_run = sub.add_parser('run-and-snapshot', help='Run an installer and snapshot around it')
    p_run.add_argument('--installer', required=True)
    p_run.add_argument('--out', required=True)
    p_run.add_argument('--out-file', help='Custom filename for the JSON report (defaults to results_<timestamp>.json inside --out)')
    p_run.add_argument('--paths', nargs='*', default=DEFAULT_WATCH_PATHS)
    p_run.add_argument('--wait', type=int, default=5)
    p_run.add_argument('--path-pattern', help='Only include files whose path contains this pattern (case-insensitive)')
    p_run.add_argument('--extensions', help='Comma-separated glob patterns to include (e.g., "*.exe,*.txt")')
    p_run.add_argument('--extensions-exclude', help='Comma-separated glob patterns to exclude (e.g., "*.lnk,*.tmp")')
    p_run.add_argument('--env-placeholders', action='store_true', help='Replace known path prefixes with %%ENV%% placeholders in the JSON output')
    p_run.add_argument('--verbose', action='store_true', help='Print detailed progress information')

    p_check = sub.add_parser('check', help='Validate a snapshot report against the current filesystem')
    p_check.add_argument('--report', required=True, help='Path to a JSON report generated by run-and-snapshot')
    p_check.add_argument('--verbose', action='store_true', help='Print detailed progress information')

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
            out_filename=args.out_file,
        )
        return

    if args.cmd == 'check':
        exit_code = check_report(args.report, verbose=args.verbose)
        sys.exit(exit_code)

    parser.print_help()


if __name__ == '__main__':
    main()
