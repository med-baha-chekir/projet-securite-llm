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
        secret_dans_prompt=interrupteur("SECRET_DANS_PROMPT", False),
    )
