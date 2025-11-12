# Windows Installer Monitor

Outil en Python pour lancer un installeur Windows (.exe), capturer l’état de certains dossiers avant/après et produire un rapport JSON des fichiers ajoutés, supprimés ou modifiés.

## Fonctionnalités principales
- **run-and-snapshot** : lance l’installeur, prend deux instantanés des chemins surveillés et produit la liste des fichiers ajoutés/supprimés/modifiés.
- Filtrage des fichiers sur une sous-chaîne (`--path-pattern`) et calcul automatique du `sha256` pour chaque fichier retenu.

## Installation
```bash
python -m venv .venv
source .venv/Scripts/activate  # ou .venv/bin/activate
pip install -r requirements.txt
```
> Pas de dépendances externes obligatoires : Python 3.8+ suffit.

## Utilisation rapide
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

## Notes d’utilisation
- Le script doit être exécuté sur Windows et idéalement en administrateur pour couvrir tout le disque.
- Pour limiter l’empreinte, gardez des chemins ciblés et combinez avec `--path-pattern`.
- Les instantanés peuvent être volumineux si vous surveillez `C:\` en entier ; privilégiez une VM ou un bac à sable.
- Aucun module tiers n’est requis, mais créer un environnement virtuel dédié reste recommandé.

## Générer un exécutable
```bash
pip install pyinstaller
pyinstaller --onefile windows_installer_monitor.py
```
Le binaire se trouvera dans `dist/windows_installer_monitor.exe`. Ajoutez `--icon` ou `--noconsole` selon vos besoins.

## Limitations
- Pas d’accès aux journaux bas niveau (pas de driver kernel, ni ETW).
- Le script ne suit plus les modifications du registre, uniquement les fichiers.
- Le calcul SHA-256 peut rallonger le temps de capture sur de très gros fichiers.

## Licence
Projet fourni tel quel pour investigation en environnement contrôlé (VM, sandbox). Ajustez les chemins/règles à vos cas d’usage.
