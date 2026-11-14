"""
Configuration du laboratoire, lue à UN SEUL endroit.

Les valeurs viennent des variables d'environnement :
- dans Docker, elles sont fournies par docker-compose (fichier .env) ;
- sur ta machine, elles sont lues directement dans le fichier .env.

Comme A et B utilisent cette même fonction, ils reçoivent exactement
les mêmes paramètres (modèle, température, graine...).
"""

import os
from dataclasses import dataclass
from pathlib import Path

# Racine du projet : app/shared/config.py -> remonter de 2 dossiers
RACINE = Path(__file__).resolve().parents[2]


def charger_fichier_env(fichier: Path) -> None:
    """
    Lit un fichier .env (lignes CLE=VALEUR) et place les valeurs dans
    os.environ. Une variable déjà définie (par Docker par exemple) est
    prioritaire : on ne l'écrase pas.
    """
    if not fichier.exists():
        return
    for ligne in fichier.read_text(encoding="utf-8").splitlines():
        ligne = ligne.strip()
        if not ligne or ligne.startswith("#") or "=" not in ligne:
            continue
        cle, valeur = ligne.split("=", 1)
        os.environ.setdefault(cle.strip(), valeur.strip())


@dataclass(frozen=True)  # frozen : la configuration ne peut pas être modifiée par erreur
class Config:
    modele: str
    modele_embeddings: str
    ollama_url: str
    temperature: float
    graine: int
    repetitions: int
    canary: str
    dossier_documents: Path
    fichier_clients: Path
    dossier_logs: Path


def charger_config(fichier_env: Path = RACINE / ".env") -> Config:
    """Construit la configuration à partir de l'environnement."""
    charger_fichier_env(fichier_env)
    return Config(
        modele=os.environ.get("MODEL_NAME", "llama3.1:8b"),
        modele_embeddings=os.environ.get("EMBED_MODEL", "nomic-embed-text"),
        ollama_url=os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434"),
        temperature=float(os.environ.get("LLM_TEMPERATURE", "0.7")),
        graine=int(os.environ.get("LLM_SEED", "42")),
        repetitions=int(os.environ.get("N_REPETITIONS", "5")),
        canary=os.environ.get("CANARY_SECRET", ""),
        dossier_documents=RACINE / "data" / "documents",
        fichier_clients=RACINE / "data" / "customers.json",
        dossier_logs=RACINE / "logs",
    )
