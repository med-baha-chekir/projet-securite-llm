"""
API de la version B (sécurisée).

Lancement local :   uvicorn app.secure.main:app --port 8001
Dans Docker :       service « app-secure » (réseau interne uniquement)

Chemin d'une question (identique à la version A, plus les protections) :
  question -> FILTRE D'ENTRÉE -> CLASSIFIEUR -> recherche RAG -> prompt durci -> modèle (+ outils)
           -> journal -> réponse

Le modèle, les données, le RAG et les outils viennent de app/shared/, comme
pour A : les deux versions ne diffèrent QUE par les protections.
Protections en place pour l'instant : prompt système durci, filtre d'entrée,
classifieur de sécurité.
"""

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

from app.secure.guards import classifieur, filtre_entree
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


MESSAGE_DE_REFUS = ("Désolé, je ne peux pas traiter cette demande. "
                    "Je peux vous aider pour vos contrats, factures et démarches Brumelec.")


def refuser(question: Question, motif: str, debut: float) -> dict:
    """
    Réponse renvoyée quand une protection BLOQUE la requête : le modèle n'est pas appelé.
    Le motif est écrit dans le journal (alerte), mais PAS dans la réponse : on ne dit
    pas à l'attaquant quelle règle l'a arrêté.
    """
    resultat = {"version": VERSION, "reponse": MESSAGE_DE_REFUS, "outils_appeles": [],
                "sources": [], "latence_s": round(time.perf_counter() - debut, 3),
                "bloque": True}
    journaliser(config.dossier_logs, VERSION,
                {"id_client": question.id_client, "graine": question.graine,
                 "question": question.message[:500],   # un message géant n'est pas recopié en entier
                 "protections": protections.actives(), "alerte": motif, **resultat})
    return resultat


@app.get("/sante")
def sante():
    return {"statut": "ok", "version": VERSION, "modele": config.modele,
            "protections": protections.actives()}


@app.post("/chat")
def chat(question: Question):
    debut = time.perf_counter()
    message = question.message

    # 0. Filtre d'entrée : le modèle ne voit jamais un message refusé
    if protections.taille_max and not filtre_entree.taille_acceptable(message):
        return refuser(question, "taille_max", debut)
    if protections.filtre_injection:
        message = filtre_entree.nettoyer(message)   # caractères invisibles retirés
        regle = filtre_entree.detecter_injection(message)
        if regle:
            return refuser(question, f"injection:{regle}", debut)
    # Le classifieur passe APRÈS les filtres rapides : inutile d'appeler un modèle
    # pour un message déjà refusé
    if protections.classifieur:
        motif = classifieur.classer(config, message)
        if motif:
            return refuser(question, f"classifieur:{motif}", debut)

    # 1. Recherche des passages utiles dans la documentation
    passages = base.rechercher(message, k=3)

    # 2. Prompt système (durci, sans secret)
    messages = [
        {"role": "system", "content": prompt_systeme(question.id_client, passages)},
        {"role": "user", "content": message},
    ]

    # 3. Appel au modèle (les outils ne sont pas encore restreints : protection à venir)
    reponse = discuter_avec_outils(config, messages, SCHEMAS_OUTILS, outils.fonctions(),
                                   graine=question.graine)

    # 4. Journal et réponse. « bloque » vaut True seulement dans refuser().
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
