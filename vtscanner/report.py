from __future__ import annotations

from pathlib import Path

from colorama import Fore, Style

from .config import MAX_ENGINES_SHOWN, VT_GUI_BASE
from .hashing import format_epoch, human_size

SEP = "=" * 64


def _line(label: str, value: str) -> str:
    return f" {label:<18}: {value}"


def print_not_found(file_path: Path, hashes: dict) -> None:
    print(SEP)
    print(_line("Fichier analysé", file_path.name))
    print(_line("SHA256", hashes["sha256"]))
    print(SEP)
    print(
        f" {Fore.YELLOW}Ce fichier est INCONNU de VirusTotal.{Style.RESET_ALL}\n"
        " Son hash n'a jamais été soumis/scanné — aucun verdict possible "
        "sans l'envoyer pour analyse."
    )
    print(SEP)


def print_report(file_path: Path, hashes: dict, vt_data: dict, show_all_engines: bool) -> None:
    local_size = file_path.stat().st_size
    attrs = vt_data["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
    threat_info = attrs.get("popular_threat_classification", {})
    total_votes = attrs.get("total_votes", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    timeout = stats.get("timeout", 0)
    total_engines = malicious + suspicious + harmless + undetected + timeout

    vt_name = attrs.get("meaningful_name") or (attrs.get("names") or [file_path.name])[0]
    sha256 = hashes["sha256"]
    report_link = f"{VT_GUI_BASE}/{sha256}"

    # --- Identité du fichier ---
    print(SEP)
    print(f" {Style.BRIGHT}Fichier analysé : {file_path.name}{Style.RESET_ALL}")
    print(_line("Nom (VirusTotal)", vt_name))
    print(_line("Taille", human_size(attrs.get("size", local_size))))
    print(_line("Type de fichier", attrs.get("type_description", "inconnu")))
    print(_line("MD5", hashes["md5"]))
    print(_line("SHA1", hashes["sha1"]))
    print(_line("SHA256", sha256))
    print(SEP)

    # --- Verdict / type de menace ---
    threat_label = threat_info.get("suggested_threat_label")
    threat_category = (threat_info.get("popular_threat_category") or [{}])
    category_value = threat_category[0].get("value") if threat_category else None

    color = Fore.RED if malicious > 0 else Fore.GREEN
    ratio = f"{malicious} / {total_engines} moteurs"
    print(f" {color}{Style.BRIGHT}Détections       : {ratio}{Style.RESET_ALL}")
    print(_line("Suspicious", str(suspicious)))
    if threat_label:
        print(f" {Fore.RED}{_line('Type de menace', threat_label)}{Style.RESET_ALL}")
    if category_value:
        print(_line("Catégorie", category_value))

    tags = attrs.get("tags") or []
    if tags:
        print(_line("Tags", ", ".join(tags)))

    print(_line("Réputation VT", str(attrs.get("reputation", 0))))
    print(
        _line(
            "Votes communauté",
            f"{total_votes.get('harmless', 0)} sain(s) / "
            f"{total_votes.get('malicious', 0)} malveillant(s)",
        )
    )
    print(_line("1ère soumission", format_epoch(attrs.get("first_submission_date"))))
    print(_line("Dernière analyse", format_epoch(attrs.get("last_analysis_date"))))
    print(_line("Rapport complet", report_link))
    print(SEP)

    # --- Détail des moteurs ---
    flagged = {
        engine: info
        for engine, info in results.items()
        if info.get("category") in ("malicious", "suspicious")
    }
    if flagged:
        print(f" {Style.BRIGHT}Moteurs ayant flaggé le fichier :{Style.RESET_ALL}")
        items = list(flagged.items())
        shown = items if show_all_engines else items[:MAX_ENGINES_SHOWN]
        for engine, info in shown:
            verdict = info.get("result") or "(non nommé)"
            cat = info.get("category")
            tag_color = Fore.RED if cat == "malicious" else Fore.YELLOW
            print(f"   - {engine:<22} {tag_color}{verdict}{Style.RESET_ALL}")
        remaining = len(items) - len(shown)
        if remaining > 0:
            print(f"   ... et {remaining} autre(s) (relance avec --all-engines pour tout voir)")
        print(SEP)

    if malicious > 0:
        print(f" {Fore.RED}{Style.BRIGHT}Fichier détecté comme MALVEILLANT.{Style.RESET_ALL}")
    elif suspicious > 0:
        print(f" {Fore.YELLOW}{Style.BRIGHT}Fichier jugé SUSPICIEUX par au moins un moteur.{Style.RESET_ALL}")
    else:
        print(f" {Fore.GREEN}Aucun moteur ne détecte ce fichier comme malveillant.{Style.RESET_ALL}")
    print(SEP)
