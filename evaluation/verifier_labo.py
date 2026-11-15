"""
Vérification du labo EN FONCTIONNEMENT (tests d'intégration).

Les tests pytest simulent le modèle et la recherche RAG. Ceux qui ont besoin du
VRAI Ollama ne peuvent pas tourner depuis ta machine : depuis la protection
« port d'Ollama fermé », il n'est joignable que par le réseau interne du labo.
Ce script les rejoue donc DANS le labo :

    docker compose --profile outils run --rm --entrypoint python campagne -m evaluation.verifier_labo

Il vérifie :
  1. que la recherche RAG retrouve le bon document (vrais embeddings) ;
  2. que les versions A et B répondent sur /sante ;
  3. que B a bien toutes ses protections activées.
Code de sortie 0 si tout est bon, 1 sinon.
"""

import json
import sys
import urllib.request

from app.shared.config import charger_config
from app.shared.rag import BaseDocumentaire
from evaluation.campagne import URLS

CAS_RAG = [
    ("Quel est le prix du kWh ?", "tarifs.md"),
    ("Comment économiser de l'énergie chez moi ?", "guide_economies_energie.md"),
    ("Comment être remboursé ?", "politique_remboursement.md"),
]
PROTECTIONS_B = {"prompt_durci", "taille_max", "filtre_injection", "classifieur", "documents",
                 "outils", "confirmation", "debit", "taille_reponse", "minimisation",
                 "sortie_secrets", "sortie_donnees", "sortie_html", "journal_masque"}


def verifier() -> list[str]:
    """Renvoie la liste des problèmes trouvés (vide = tout va bien)."""
    problemes = []

    base = BaseDocumentaire(charger_config())
    base.indexer()
    for question, attendu in CAS_RAG:
        trouve = base.rechercher(question, k=1)[0]["source"]
        print(f"RAG  « {question} » -> {trouve}")
        if trouve != attendu:
            problemes.append(f"RAG : « {question} » a trouvé {trouve} au lieu de {attendu}")

    for version, url in URLS.items():
        try:
            with urllib.request.urlopen(url + "/sante", timeout=10) as r:
                sante = json.load(r)
            print(f"API  version {version} : {sante['statut']}")
        except Exception as erreur:
            problemes.append(f"version {version} injoignable : {erreur}")
            continue
        if version == "B":
            manquantes = PROTECTIONS_B - set(sante.get("protections", []))
            if manquantes:
                problemes.append(f"version B : protections désactivées {sorted(manquantes)}")
    return problemes


if __name__ == "__main__":
    problemes = verifier()
    for p in problemes:
        print("PROBLÈME :", p)
    print("Labo OK" if not problemes else f"{len(problemes)} problème(s)")
    sys.exit(1 if problemes else 0)
