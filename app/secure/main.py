"""
API de la version B (sécurisée).

Lancement local :   uvicorn app.secure.main:app --port 8001
Dans Docker :       service « app-secure » (réseau interne uniquement)

Chemin d'une question (identique à la version A, plus les protections) :
  question -> recherche RAG -> prompt -> modèle (+ outils) -> journal -> réponse

Le modèle, les données, le RAG et les outils viennent de app/shared/, comme
pour A : les deux versions ne diffèrent QUE par les protections.
Protections en place pour l'instant : prompt système durci.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from app.secure.guards.prompt_durci import construire_prompt_durci
from app.secure.protections import charger_protections
from app.shared.config import charger_config
from app.shared.journal import journaliser
from app.shared.llm import discuter_avec_outils
from app.shared.outils import SCHEMAS_OUTILS, BoiteOutils
from app.shared.rag import BaseDocumentaire
from app.vulnerable.prompt import construire_prompt_systeme

VERSION = "B"

config = charger_config()
protections = charger_protections()
base = BaseDocumentaire(config)
outils = BoiteOutils(config)


@asynccontextmanager
async def demarrage(app: FastAPI):
    """Au démarrage du serveur : indexation des documents dans ChromaDB."""
    nb = base.indexer()
    print(f"[version {VERSION}] {nb} morceaux de documents indexés")
    print(f"[version {VERSION}] réglages activés : {protections.actives()}")
    yield


app = FastAPI(title="Brumelec — version B (sécurisée)", lifespan=demarrage)


class Question(BaseModel):
    message: str                 # la question de l'utilisateur
    id_client: str = "C001"      # client « connecté »
    graine: int | None = None    # graine du modèle, fixée par la campagne pour chaque répétition


def prompt_systeme(id_client: str, passages: list[dict]) -> str:
    """Choisit le prompt selon les protections activées."""
    if not protections.prompt_durci:
        # Protection désactivée : exactement le prompt naïf de la version A
        return construire_prompt_systeme(config.canary, id_client, passages)
    canary = config.canary if protections.secret_dans_prompt else ""
    return construire_prompt_durci(id_client, passages, canary)


@app.get("/sante")
def sante():
    return {"statut": "ok", "version": VERSION, "modele": config.modele,
            "protections": protections.actives()}


@app.post("/chat")
def chat(question: Question):
    # 1. Recherche des passages utiles dans la documentation
    passages = base.rechercher(question.message, k=3)

    # 2. Prompt système (durci, sans secret)
    messages = [
        {"role": "system", "content": prompt_systeme(question.id_client, passages)},
        {"role": "user", "content": question.message},
    ]

    # 3. Appel au modèle (les outils ne sont pas encore restreints : protection à venir)
    reponse = discuter_avec_outils(config, messages, SCHEMAS_OUTILS, outils.fonctions(),
                                   graine=question.graine)

    # 4. Journal et réponse. « bloque » passera à True quand un filtre refusera une requête.
    resultat = {
        "version": VERSION,
        "reponse": reponse.texte,
        "outils_appeles": reponse.appels_outils,
        "sources": [p["source"] for p in passages],
        "latence_s": round(reponse.latence_s, 3),
        "bloque": False,
    }
    journaliser(config.dossier_logs, VERSION,
                {"id_client": question.id_client, "graine": question.graine,
                 "question": question.message, "protections": protections.actives(),
                 **resultat})
    return resultat
