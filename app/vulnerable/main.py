"""
API de la version A (vulnérable).

Lancement local :   uvicorn app.vulnerable.main:app --port 8000
Dans Docker :       service « app-vulnerable » (réseau interne uniquement)

Chemin d'une question :
  question -> recherche RAG -> prompt naïf -> modèle (+ outils) -> journal -> réponse
Aucune étape ne contient de protection : c'est le point de départ « AVANT ».
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from app.shared.config import charger_config
from app.shared.journal import journaliser
from app.shared.llm import discuter_avec_outils
from app.shared.outils import SCHEMAS_OUTILS, BoiteOutils
from app.shared.rag import BaseDocumentaire
from app.vulnerable.prompt import construire_prompt_systeme

VERSION = "A"

config = charger_config()
base = BaseDocumentaire(config)
outils = BoiteOutils(config)


@asynccontextmanager
async def demarrage(app: FastAPI):
    """Au démarrage du serveur : indexation des documents dans ChromaDB."""
    nb = base.indexer()
    print(f"[version {VERSION}] {nb} morceaux de documents indexés")
    yield


app = FastAPI(title="Brumelec — version A (vulnérable)", lifespan=demarrage)


class Question(BaseModel):
    message: str                 # la question de l'utilisateur
    id_client: str = "C001"      # client « connecté » (simple déclaration, rien n'est vérifié)
    graine: int | None = None    # graine du modèle, fixée par la campagne pour chaque répétition


@app.get("/sante")
def sante():
    return {"statut": "ok", "version": VERSION, "modele": config.modele}


@app.post("/chat")
def chat(question: Question):
    # 1. Recherche des passages utiles dans la documentation (texte brut)
    passages = base.rechercher(question.message, k=3)

    # 2. Prompt naïf : canary + documents collés tels quels
    messages = [
        {"role": "system",
         "content": construire_prompt_systeme(config.canary, question.id_client, passages)},
        {"role": "user", "content": question.message},
    ]

    # 3. Appel au modèle, avec TOUS les outils et sans aucun contrôle
    reponse = discuter_avec_outils(config, messages, SCHEMAS_OUTILS, outils.fonctions(),
                                   graine=question.graine)

    # 4. Journal (sert à la mesure ; aucune alerte dans la version A)
    resultat = {
        "version": VERSION,
        "reponse": reponse.texte,
        "outils_appeles": reponse.appels_outils,
        "sources": [p["source"] for p in passages],
        "latence_s": round(reponse.latence_s, 3),
    }
    journaliser(config.dossier_logs, VERSION,
                {"id_client": question.id_client, "graine": question.graine,
                 "question": question.message, **resultat})
    return resultat
