from __future__ import annotations

import os
import sys
from pathlib import Path

VT_API_BASE = "https://www.virustotal.com/api/v3/files"
VT_GUI_BASE = "https://www.virustotal.com/gui/file"
CHUNK_SIZE = 65536  # 64 Ko — lecture par blocs pour les gros fichiers
MAX_ENGINES_SHOWN = 15  # nombre de moteurs flaggés affichés par défaut


def _load_dotenv_api_key(dotenv_path: str = ".env") -> str | None:
    path = Path(dotenv_path)
    if not path.exists():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key.strip() == "VT_API_KEY":
            return value.strip().strip('"').strip("'")
    return None


def resolve_api_key(cli_key: str | None) -> str:
    key = cli_key or os.environ.get("VT_API_KEY") or _load_dotenv_api_key()
    if not key:
        sys.exit(
            "Aucune clé API VirusTotal trouvée.\n"
            "Fournis-la via --apikey, la variable d'environnement VT_API_KEY, "
            "ou un fichier .env contenant VT_API_KEY=ta_cle"
        )
    return key
