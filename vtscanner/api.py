from __future__ import annotations

import requests

from .config import VT_API_BASE


class VirusTotalError(Exception):
    """Erreur lors de l'interrogation de l'API VirusTotal."""

class VirusTotalClient:
    def __init__(self, api_key: str, timeout: int = 30):
        self.api_key = api_key
        self.timeout = timeout

    def lookup_hash(self, file_hash: str) -> dict:
        url = f"{VT_API_BASE}/{file_hash}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(url, headers=headers, timeout=self.timeout)
        except requests.exceptions.RequestException as exc:
            raise VirusTotalError(f"Erreur réseau : {exc}") from exc

        if response.status_code == 404:
            return {"found": False}

        if response.status_code == 401:
            raise VirusTotalError("Clé API invalide ou expirée (401 Unauthorized).")

        if response.status_code == 429:
            raise VirusTotalError(
                "Quota VirusTotal dépassé (429 Too Many Requests). "
                "Attends un peu avant de relancer."
            )

        try:
            response.raise_for_status()
        except requests.exceptions.HTTPError as exc:
            raise VirusTotalError(f"Erreur API VirusTotal : {exc}") from exc

        return {"found": True, "data": response.json()["data"]}
