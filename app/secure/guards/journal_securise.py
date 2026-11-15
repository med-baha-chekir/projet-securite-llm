"""
Protection n° 9 : JOURNAL STRUCTURÉ, avec ALERTES et données MASQUÉES.

Deux besoins qui s'opposent :
  - DÉTECTER : il faut garder une trace de chaque requête pour repérer une
    attaque, la comprendre, et prouver ce qui s'est passé ;
  - PROTÉGER : un journal qui recopie tout devient lui-même une fuite. Celui de
    la version A contient les questions, les réponses, les fiches clients et le
    canary en clair : quiconque lit le fichier logs/A.jsonl voit tout (RGPD :
    un journal est un traitement de données personnelles comme un autre).

Ce module répond aux deux :

  1. STRUCTURE : chaque ligne du journal de B porte les mêmes champs
       niveau     « info » (rien à signaler) ou « alerte »
       evenement  « requete », « requete_bloquee », « anomalie_neutralisee »,
                  « confirmation »
       alertes    liste des motifs, ex. ["injection:fausse_autorite"]
     On peut ainsi compter les attaques détectées avec un simple filtre
     (métrique « détection » du projet) ;

  2. MASQUAGE, appliqué à TOUT ce qui est écrit (question, réponse, arguments
     et résultats des outils) :
       - le canary et les codes internes ;
       - le nom, l'e-mail, le téléphone et l'adresse de TOUS les clients, y
         compris le client connecté (dans la réponse, il a le droit de voir ses
         données ; dans le journal, personne n'a besoin de les lire) ;
       - toute adresse e-mail et tout numéro de téléphone, même inconnus.
     L'identifiant du client (C001) est gardé : il permet de relier les
     événements entre eux sans révéler qui est la personne (pseudonyme).

LIMITES (à dire dans le rapport) :
  - une donnée personnelle écrite librement par l'utilisateur (« j'habite au 3
    rue Machin ») n'est pas reconnue ;
  - le journal des actions simulées (logs/actions_simulees.jsonl) est écrit par
    le code partagé avec la version A : il n'est pas masqué ;
  - les fichiers ne sont ni chiffrés ni signés : un administrateur peut les
    lire ou les modifier.
"""

import re

from app.secure.guards import filtre_sortie

EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
TELEPHONE = re.compile(r"(?<!\d)(?:\+33[ .]?|0)[1-9](?:[ .\-]?\d{2}){4}(?!\d)")

# Champs techniques jamais modifiés (ils ne contiennent pas de texte libre)
CHAMPS_INTACTS = {"horodatage", "version", "id_client", "graine", "protections", "niveau",
                  "evenement", "alertes", "sources", "latence_s", "bloque", "confirmation"}


def masquer_texte(texte: str, canary: str, clients: dict) -> str:
    propre = filtre_sortie.masquer_secrets(texte, canary, [])
    # id_client vide : aucun client n'est « le client connecté », tous sont masqués
    propre = filtre_sortie.masquer_donnees_personnelles(propre, clients, "", [])
    propre = EMAIL.sub("[EMAIL]", propre)
    return TELEPHONE.sub("[TÉLÉPHONE]", propre)


def masquer(valeur, canary: str, clients: dict):
    """Masque tous les textes d'un événement (dictionnaires et listes parcourus en entier)."""
    if isinstance(valeur, str):
        return masquer_texte(valeur, canary, clients)
    if isinstance(valeur, dict):
        return {cle: v if cle in CHAMPS_INTACTS else masquer(v, canary, clients)
                for cle, v in valeur.items()}
    if isinstance(valeur, list):
        return [masquer(v, canary, clients) for v in valeur]
    return valeur


def structurer(evenement: dict, alertes: list[str], bloque: bool = False,
               type_evenement: str | None = None) -> dict:
    """Ajoute les champs communs : niveau, evenement, alertes (sans doublon)."""
    alertes = list(dict.fromkeys(alertes))
    if type_evenement is None:
        type_evenement = ("requete_bloquee" if bloque
                          else "anomalie_neutralisee" if alertes else "requete")
    return {"niveau": "alerte" if alertes else "info", "evenement": type_evenement,
            "alertes": alertes, **evenement}
