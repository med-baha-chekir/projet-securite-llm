"""
Interrupteurs des protections de la version B.

Chaque protection s'active ou se désactive avec une variable d'environnement
(1 = activée, 0 = désactivée). On peut ainsi mesurer l'effet de CHAQUE
protection séparément (analyse par protection, phase P6) :

    PROTECTION_PROMPT_DURCI=0 docker compose up -d app-secure

Toutes les protections désactivées, la version B se comporte comme la version A.
"""

import os
from dataclasses import asdict, dataclass


def interrupteur(nom: str, defaut: bool) -> bool:
    """Lit une variable d'environnement « 0 / 1 » (vide ou absente = valeur par défaut)."""
    valeur = os.environ.get(nom, "").strip().lower()
    if not valeur:
        return defaut
    return valeur in ("1", "true", "oui", "on")


@dataclass(frozen=True)
class Protections:
    # Prompt système durci : règles de sécurité explicites, plus d'obéissance totale
    prompt_durci: bool
    # Filtre d'entrée : message trop long refusé (A9)
    taille_max: bool
    # Filtre d'entrée : nettoyage des caractères invisibles + détection d'injection (A1, A2, A3, A10)
    filtre_injection: bool
    # Classifieur de sécurité Llama Guard : juge le sens du message (contenu dangereux)
    classifieur: bool
    # Documents du RAG et résultats d'outils : nettoyage + délimitation (A5)
    documents: bool
    # Outils en moindre privilège : chaque outil n'agit que pour le client connecté (A6, A8)
    outils: bool
    # Remboursement et e-mail mis en attente d'une confirmation du client
    confirmation: bool
    # Minimisation : fiche client réduite, documents réservés au personnel écartés (A4, A8)
    minimisation: bool
    # Filtre de sortie : canary et codes internes masqués (A3, A4)
    sortie_secrets: bool
    # Filtre de sortie : données personnelles des autres clients masquées (A8)
    sortie_donnees: bool
    # Filtre de sortie : images, liens externes et HTML neutralisés (A7)
    sortie_html: bool
    # RÉGLAGE D'ANALYSE, désactivé par défaut. La vraie défense est de ne PAS mettre
    # de secret dans le prompt. Mais sans secret, les fuites tombent à zéro quoi
    # qu'il arrive, et on ne peut plus mesurer l'effet du filtre de sortie seul.
    # Ce réglage remet le canary dans le prompt durci, uniquement pour cette mesure.
    secret_dans_prompt: bool

    def actives(self) -> list[str]:
        """Noms des réglages activés (écrits dans le journal et dans /sante)."""
        return [nom for nom, active in asdict(self).items() if active]


def charger_protections() -> Protections:
    return Protections(
        prompt_durci=interrupteur("PROTECTION_PROMPT_DURCI", True),
        taille_max=interrupteur("PROTECTION_TAILLE_MAX", True),
        filtre_injection=interrupteur("PROTECTION_FILTRE_INJECTION", True),
        classifieur=interrupteur("PROTECTION_CLASSIFIEUR", True),
        documents=interrupteur("PROTECTION_DOCUMENTS", True),
        outils=interrupteur("PROTECTION_OUTILS", True),
        confirmation=interrupteur("PROTECTION_CONFIRMATION", True),
        minimisation=interrupteur("PROTECTION_MINIMISATION", True),
        sortie_secrets=interrupteur("PROTECTION_SORTIE_SECRETS", True),
        sortie_donnees=interrupteur("PROTECTION_SORTIE_DONNEES", True),
        sortie_html=interrupteur("PROTECTION_SORTIE_HTML", True),
        secret_dans_prompt=interrupteur("SECRET_DANS_PROMPT", False),
    )
