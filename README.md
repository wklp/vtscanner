# vtscanner

Scanner de fichiers en ligne de commande qui calcule les empreintes **MD5 /
SHA1 / SHA256** d'un fichier local et interroge l'**API VirusTotal v3** pour
savoir s'il est connu comme malveillant — sans jamais uploader le fichier
lui-même (recherche par hash uniquement).

## Fonctionnalités

- Calcul MD5 / SHA1 / SHA256 (lecture par blocs, compatible gros fichiers)
- Requête HTTPS vers l'API VirusTotal (`/api/v3/files/{hash}`)
- Nombre de détections malveillantes / nombre total de moteurs antivirus
- Nom et taille du fichier (local + tel que connu par VirusTotal)
- Famille de menace suspectée (`popular_threat_classification`) quand VT la fournit
- Dates de première soumission et dernière analyse
- Réputation et votes de la communauté VirusTotal
- Détail des moteurs antivirus ayant flaggé le fichier, avec le nom qu'ils lui donnent
- Lien direct vers le rapport VirusTotal
- Sortie colorée dans le terminal (rouge = malveillant, vert = sain)

## Structure du projet

```
vtscanner/
├── vtscanner/
│   ├── __init__.py
│   ├── __main__.py      # python -m vtscanner
│   ├── cli.py            # point d'entrée, argparse
│   ├── config.py         # résolution de la clé API
│   ├── hashing.py        # MD5/SHA1/SHA256 + utilitaires
│   ├── api.py             # client VirusTotal
│   └── report.py          # affichage du rapport
├── tests/
│   └── test_hashing.py
├── requirements.txt
├── pyproject.toml
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## Installation

```bash
git clone https://github.com/wklp/vtscanner
cd vtscanner
pip install -r requirements.txt
```

Ou en mode package installable (ajoute la commande `vtscan`) :

```bash
pip install -e .
```

## Clé API

Il faut une clé API VirusTotal (gratuite, compte VirusTotal classique).
Elle est lue dans cet ordre de priorité :

1. `--apikey TA_CLE`
2. Variable d'environnement `VT_API_KEY`
3. Fichier `.env` (voir `.env.example`)

## Usage

```bash
python -m vtscanner chemin/vers/fichier
# ou, si installé avec pip install -e . :
vtscan chemin/vers/fichier --apikey TA_CLE
```

Options :

| Option          | Description                                         |
|-----------------|------------------------------------------------------|
| `--apikey`      | Clé API VirusTotal                                   |
| `--all-engines` | Affiche tous les moteurs flaggés (pas seulement 15)  |

## Exemple de sortie

```
================================================================
Fichier analysé : exemple.exe
Nom (VirusTotal) : exemple.exe
Taille            : 1.73 Mo
Type de fichier   : Win32 EXE
MD5               : ...
SHA1              : ...
SHA256            : ...
================================================================
Détections        : 18 / 70 moteurs
Suspicious        : 0
Type de menace     : trojan.stealer/xyz
Catégorie          : trojan
Réputation VT      : -12
Votes communauté   : 2 sain(s) / 9 malveillant(s)
1ère soumission    : 2026-09-01 10:12 UTC
Dernière analyse   : 2026-10-13 08:40 UTC
Rapport complet     : https://www.virustotal.com/gui/file/<sha256>
================================================================
Moteurs ayant flaggé le fichier :
   - Kaspersky               HEUR:Trojan.Win32.Generic
   - Microsoft                Trojan:Win32/Wacatac.B!ml
   ...
================================================================
Fichier détecté comme MALVEILLANT.
================================================================
```

## Tests

```bash
pip install pytest
pytest
```

## Limitations

- Interroge VirusTotal **par hash uniquement** : il n'uploade jamais le
  fichier. Si le hash est inconnu de VirusTotal, aucun verdict n'est possible.
- L'API publique VirusTotal est limitée en requêtes/minute et/jour selon le
  type de compte.

## Licence

MIT — voir [LICENSE](LICENSE).
