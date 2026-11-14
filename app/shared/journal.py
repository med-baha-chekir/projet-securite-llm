"""
Journalisation des échanges au format JSON Lines (une ligne JSON par événement).

Exemple de ligne dans logs/A.jsonl :
{"horodatage": "2026-11-14T10:00:00+00:00", "version": "A", "question": "...", ...}

Ce format est simple à relire avec pandas pour calculer les métriques.
Dans la version A, ce journal sert seulement à la mesure : il n'y a ni
détection ni alerte. Les alertes seront une protection de la version B.
"""

import json
from datetime import datetime, timezone
from pathlib import Path


def journaliser(dossier_logs: Path, version: str, evenement: dict) -> dict:
    """Ajoute un événement à la fin du fichier logs/<version>.jsonl et le renvoie."""
    dossier_logs.mkdir(parents=True, exist_ok=True)
    ligne = {
        "horodatage": datetime.now(timezone.utc).isoformat(),
        "version": version,
        **evenement,
    }
    with open(dossier_logs / f"{version}.jsonl", "a", encoding="utf-8") as f:
        # ensure_ascii=False : garde les accents lisibles ; default=str : convertit
        # les objets non JSON (dates...) en texte au lieu de planter
        f.write(json.dumps(ligne, ensure_ascii=False, default=str) + "\n")
    return ligne
