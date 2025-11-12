# Windows Installer Monitor

Outil en Python pour surveiller ce qu’un installeur Windows (.exe) ajoute ou modifie sur le système et produit des traces JSON exploitables.

## Fonctionnalités principales
- **run-and-snapshot** : lance l’installeur, prend deux instantanés des chemins surveillés et produit la liste des fichiers ajoutés/supprimés/modifiés.
- **snapshot** : compare deux instantanés JSON déjà capturés et génère un diff.
- **live** : observe en direct des dossiers via `watchdog` et enregistre en parallèle les processus via `psutil`.
- Filtrage des fichiers sur une sous-chaîne (`--path-pattern`) et calcul automatique du `sha256` pour chaque fichier retenu.

## Installation
```bash
python -m venv .venv
source .venv/Scripts/activate  # ou .venv/bin/activate
pip install -r requirements.txt
```
> Dépendances : `psutil`, `watchdog`, plus la bibliothèque standard Python 3.8+.

## Utilisation rapide
### Lancer un installeur et capturer les changements
```bash
python windows_installer_monitor.py run-and-snapshot \
  --installer "C:\Chemin\setup.exe" \
  --out C:\chemin\vers\resultats \
  --paths "C:\Program Files" "C:\Program Files (x86)" "C:\Users" \
  --path-pattern obsidian
```
- `--paths` : racines à explorer (par défaut celles fournies dans `DEFAULT_WATCH_PATHS`).
- `--path-pattern` : optionnel, conserve uniquement les fichiers dont le chemin contient la chaîne (insensible à la casse). Sans ce filtre, tous les fichiers des chemins surveillés seront listés.
- Le résultat est un fichier `results_<timestamp>.json` contenant les sections `files.added`, `files.removed` et `files.changed`. Chaque entrée garde uniquement la somme `sha256`.

### Différencier deux captures existantes
```bash
python windows_installer_monitor.py snapshot \
  --before avant.json \
  --after apres.json \
  --out C:\chemin\vers\diff
```

### Mode live (surveillance temps réel)
```bash
python windows_installer_monitor.py live \
  --installer "C:\Chemin\setup.exe" \
  --watch "C:\Program Files" "C:\Temp" \
  --out C:\chemin\vers\resultats \
  --interval 0.7
```
Produit `live_results_<timestamp>.json` avec les événements watchdog (`fs_events`) et les instantanés de processus (`process_snapshots`).

## Notes d’utilisation
- Le script doit être exécuté sur Windows et idéalement en administrateur pour couvrir tout le disque.
- Pour limiter l’empreinte, gardez des chemins ciblés et combinez avec `--path-pattern`.
- Les instantanés peuvent être volumineux si vous surveillez `C:\` en entier ; privilégiez une VM ou un bac à sable.
- `psutil` et `watchdog` ne sont pas inclus dans Python standard, installez le `requirements.txt` avant toute exécution.

## Générer un exécutable
```bash
pip install pyinstaller
pyinstaller --onefile windows_installer_monitor.py
```
Le binaire se trouvera dans `dist/windows_installer_monitor.exe`. Ajoutez `--icon` ou `--noconsole` selon vos besoins.

## Limitations
- Pas d’accès aux journaux bas niveau (pas de driver kernel, ni ETW).
- Le script ne suit plus les modifications du registre, uniquement les fichiers et les processus.
- Le calcul SHA-256 peut rallonger le temps de capture sur de très gros fichiers.

## Licence
Projet fourni tel quel pour investigation en environnement contrôlé (VM, sandbox). Ajustez les chemins/règles à vos cas d’usage.
