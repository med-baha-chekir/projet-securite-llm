"""
API de la version B (sécurisée).

Lancement local :   uvicorn app.secure.main:app --port 8001
Dans Docker :       service « app-secure » (réseau interne uniquement)

Chemin d'une question (identique à la version A, plus les protections) :
  question -> LIMITE DE DÉBIT -> FILTRE D'ENTRÉE -> CLASSIFIEUR -> recherche RAG -> NETTOYAGE DES DOCUMENTS
           -> OUTILS CONTRÔLÉS -> FILTRE DE SORTIE -> prompt durci -> modèle (+ outils)
           -> journal -> réponse

Le modèle, les données, le RAG et les outils viennent de app/shared/, comme
pour A : les deux versions ne diffèrent QUE par les protections.
Protections en place pour l'instant : prompt système durci, filtre d'entrée,
classifieur de sécurité, nettoyage et délimitation des documents et des résultats d'outils,
outils en moindre privilège avec confirmation, minimisation des données,
filtre de sortie, limite de débit et taille maximale de réponse,
journal structuré avec alertes et données masquées.
"""

import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.secure.guards import (classifieur, documents, filtre_entree, filtre_sortie,
                               journal_securise, limites, minimisation, outils_proteges)
from app.secure.guards.prompt_durci import REGLES, construire_prompt_durci
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
limiteur = limites.LimiteurDebit()   # un seau à jetons par client


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
    # Délimitation par balises <document> si la protection des documents est activée
    documentation = documents.delimiter(passages) if protections.documents else None
    return construire_prompt_durci(id_client, passages, canary, documentation)


VERROU_JOURNAL = threading.Lock()


def ecrire_journal(evenement: dict, alertes: list[str], bloque: bool = False,
                   type_evenement: str | None = None) -> None:
    """
    Toutes les écritures du journal de B passent par ici : même structure pour
    chaque ligne (niveau, evenement, alertes), et données sensibles masquées.
    """
    ligne = journal_securise.structurer(evenement, alertes, bloque, type_evenement)
    if protections.journal_masque:
        ligne = journal_securise.masquer(ligne, config.canary, outils.clients)
    # Verrou : pendant une rafale, plusieurs requêtes écrivent en même temps. Sans
    # lui, des lignes étaient perdues (constaté le 15/11/2026 : 38 refus de débit
    # journalisés sur 50). Une seule écriture à la fois.
    with VERROU_JOURNAL:
        journaliser(config.dossier_logs, VERSION, ligne)


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
    ecrire_journal({"id_client": question.id_client, "graine": question.graine,
                    "question": question.message[:500],   # un message géant n'est pas recopié en entier
                    "protections": protections.actives(), **resultat},
                   alertes=[motif], bloque=True)
    return resultat


@app.get("/sante")
def sante():
    return {"statut": "ok", "version": VERSION, "modele": config.modele,
            "protections": protections.actives()}


@app.post("/chat")
def chat(question: Question):
    debut = time.perf_counter()
    message = question.message

    # Limite de débit : contrôlée en premier, avant tout calcul
    if protections.debit and not limiteur.autoriser(question.id_client.strip().upper()):
        # Code HTTP 429 « trop de requêtes » : c'est le code standard pour ce cas
        return JSONResponse(status_code=429, content=refuser(question, "debit", debut))

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
    if protections.minimisation:
        # Un document réservé au personnel n'est jamais donné au chatbot des clients.
        # On en demande un de plus pour garder 3 passages après ce tri.
        passages = minimisation.retirer_documents_internes(base.rechercher(message, k=4))[:3]
    else:
        passages = base.rechercher(message, k=3)

    # 1 bis. Les documents et les résultats d'outils sont des DONNÉES : on retire ce
    # qui ressemble à des ordres cachés. Les anomalies deviennent des alertes.
    alertes = []
    fonctions = outils.fonctions()
    if protections.minimisation:
        # La fiche client transmise au modèle ne contient que les champs utiles
        fonctions = minimisation.proteger_outils(fonctions)
    # Moindre privilège : chaque outil vérifie qu'il agit pour le client connecté.
    # Les actions sensibles autorisées attendent la confirmation du client.
    a_confirmer = []
    if protections.outils:
        fonctions = outils_proteges.proteger_outils(
            fonctions, outils.clients, question.id_client, alertes,
            confirmation=protections.confirmation, en_attente=a_confirmer)
    if protections.documents:
        passages, alertes_documents = documents.nettoyer_passages(passages)
        alertes += alertes_documents
        fonctions = documents.proteger_outils(fonctions, alertes)
    if protections.sortie_secrets:
        # Un secret ne doit pas sortir non plus par le texte d'un e-mail
        fonctions = filtre_sortie.proteger_outils(fonctions, config.canary, alertes)

    # 2. Prompt système (durci, sans secret)
    messages = [
        {"role": "system", "content": prompt_systeme(question.id_client, passages)},
        {"role": "user", "content": message},
    ]

    # 3. Appel au modèle, avec les outils contrôlés
    # La génération s'arrête après MAX_TOKENS_REPONSE tokens (réponse sans fin impossible)
    options = {"num_predict": limites.MAX_TOKENS_REPONSE} if protections.taille_reponse else None
    reponse = discuter_avec_outils(config, messages, SCHEMAS_OUTILS, fonctions,
                                   graine=question.graine, options=options)

    # 4. Filtre de sortie : la réponse est corrigée par du code avant d'être renvoyée
    texte, appels = reponse.texte, reponse.appels_outils
    if protections.sortie_secrets:
        texte = filtre_sortie.masquer_secrets(texte, config.canary, alertes)
        # Les consignes internes ne doivent pas être recopiées (A3)
        if filtre_sortie.contient_consignes(texte, REGLES):
            alertes.append("sortie: consignes internes recopiées, réponse remplacée")
            texte = filtre_sortie.REPONSE_SECRET
        # Les arguments des outils sont affichés dans l'interface : masqués aussi
        appels = [{**a, "arguments": filtre_sortie.masquer_arguments(
                       a.get("arguments", {}), config.canary, [])} for a in appels]
    if protections.sortie_donnees:
        texte = filtre_sortie.masquer_donnees_personnelles(
            texte, outils.clients, question.id_client, alertes)
    if protections.sortie_html:
        texte = filtre_sortie.neutraliser_contenu_actif(texte, alertes)

    # 5. Journal et réponse. « bloque » vaut True seulement dans refuser().
    resultat = {
        "version": VERSION,
        "reponse": texte,
        "outils_appeles": appels,
        "sources": [p["source"] for p in passages],
        "latence_s": round(reponse.latence_s, 3),
        "bloque": False,
        # Actions que le client doit confirmer lui-même (POST /confirmer)
        "a_confirmer": a_confirmer,
    }
    # Requête traitée. S'il y a des alertes, une anomalie a été trouvée et neutralisée.
    ecrire_journal({"id_client": question.id_client, "graine": question.graine,
                    "question": question.message, "protections": protections.actives(),
                    **resultat}, alertes)
    return resultat


class Confirmation(BaseModel):
    id_action: str               # identifiant reçu dans « a_confirmer »
    id_client: str = "C001"      # client « connecté »


@app.post("/confirmer")
def confirmer(confirmation: Confirmation):
    """Le client confirme lui-même une action sensible mise en attente par /chat."""
    resultat = outils_proteges.confirmer(confirmation.id_action, confirmation.id_client,
                                         outils.fonctions())
    ecrire_journal({"id_client": confirmation.id_client, "confirmation": confirmation.id_action,
                    "resultat": resultat},
                   alertes=["confirmation refusée"] if "refuse" in resultat else [],
                   type_evenement="confirmation")
    return resultat
