"""
Protection n° 7 : MINIMISATION DES DONNÉES (scénarios A4, A8 — OWASP LLM02, RGPD).

Principe : le modèle ne peut pas divulguer ce qu'on ne lui donne pas. Plutôt que
de lui confier une donnée sensible puis d'essayer de l'empêcher d'en parler, on
ne la lui transmet PAS. C'est le principe de minimisation du RGPD (article 5) :
ne traiter que les données nécessaires à la tâche.

Deux applications :

  1. FICHE CLIENT : l'outil consulter_fiche_client ne renvoie que les champs
     utiles pour répondre à un client. La note interne (commentaires des
     conseillers : litige, précarité, impayés...) et le téléphone ne sont
     jamais transmis au modèle ;

  2. DOCUMENTS RÉSERVÉS AU PERSONNEL : un document marqué « réservé au
     personnel » n'est jamais donné à un chatbot qui parle aux clients. Dans la
     version A, la note interne (code promotionnel des employés, hausse de
     tarifs non annoncée) est indexée avec le reste et peut être récitée.

Différence avec le filtre de sortie : le filtre rattrape un secret qu'il sait
RECONNAÎTRE (un code au format STAFF-...). La minimisation protège aussi ce
qu'aucun filtre ne reconnaît, par exemple la phrase « hausse de 8 % des tarifs
prévue au 1er juillet ».

LIMITE (à dire dans le rapport) : le tri des documents repose sur une mention
écrite dans le document. Un document sensible mal étiqueté serait transmis.
Dans un vrai système, chaque document porterait un niveau de confidentialité
contrôlé au moment de l'indexation.
"""

import re

# Seuls champs de la fiche transmis au modèle
CHAMPS_UTILES = ("id", "nom", "email", "adresse", "contrat", "puissance_kva", "solde_euros")

MENTION_RESERVE = re.compile(r"r[ée]serv[ée]e?s? au personnel", re.IGNORECASE)


def minimiser_fiche(fiche: dict) -> dict:
    """Garde seulement les champs utiles. Une erreur de l'outil est renvoyée telle quelle."""
    if "erreur" in fiche or "refuse" in fiche:
        return fiche
    return {champ: fiche[champ] for champ in CHAMPS_UTILES if champ in fiche}


def proteger_outils(fonctions: dict) -> dict:
    """Remplace consulter_fiche_client par une version qui renvoie la fiche minimisée."""
    consulter = fonctions["consulter_fiche_client"]
    return {**fonctions,
            "consulter_fiche_client": lambda **arguments: minimiser_fiche(consulter(**arguments))}


def est_reserve_au_personnel(passage: dict) -> bool:
    """Vrai si le TITRE du passage (sa première ligne) porte la mention « réservé au personnel »."""
    lignes = passage["texte"].strip().splitlines()
    return bool(lignes) and MENTION_RESERVE.search(lignes[0]) is not None


def retirer_documents_internes(passages: list[dict]) -> list[dict]:
    return [p for p in passages if not est_reserve_au_personnel(p)]
