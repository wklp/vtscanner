from __future__ import annotations

import argparse
import sys
from pathlib import Path

from colorama import Fore, Style, init as colorama_init

from .api import VirusTotalClient, VirusTotalError
from .config import resolve_api_key
from .hashing import compute_hashes
from .report import print_not_found, print_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vtscan",
        description="Scanne un fichier local via l'API VirusTotal (par hash, sans upload).",
    )
    parser.add_argument("file", help="Chemin vers le fichier à analyser")
    parser.add_argument(
        "--apikey",
        help="Clé API VirusTotal (sinon lue dans VT_API_KEY ou .env)",
        default=None,
    )
    parser.add_argument(
        "--all-engines",
        action="store_true",
        help="Afficher tous les moteurs ayant flaggé le fichier",
    )
    return parser


def main() -> None:
    colorama_init()  # active les couleurs ANSI sur le terminal Windows (cmd.exe)

    args = build_parser().parse_args()

    file_path = Path(args.file)
    if not file_path.is_file():
        sys.exit(f"Fichier introuvable : {file_path}")

    api_key = resolve_api_key(args.apikey)

    print(f"{Fore.CYAN}Calcul des empreintes (MD5 / SHA1 / SHA256)...{Style.RESET_ALL}")
    hashes = compute_hashes(file_path)

    print(f"{Fore.CYAN}Requête vers VirusTotal...{Style.RESET_ALL}\n")
    client = VirusTotalClient(api_key)
    try:
        result = client.lookup_hash(hashes["sha256"])
    except VirusTotalError as exc:
        sys.exit(str(exc))

    if not result["found"]:
        print_not_found(file_path, hashes)
        return

    print_report(file_path, hashes, result["data"], args.all_engines)


if __name__ == "__main__":
    main()
