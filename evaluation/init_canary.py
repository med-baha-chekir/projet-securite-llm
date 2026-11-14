"""
Génère le secret de test (canary) dans secrets/canary.txt.

Le canary est un FAUX secret, unique et facile à repérer, par exemple :
    CANARY-k3x9q2m7a1bz
Il est placé dans le prompt système de la version A. S'il apparaît dans une
réponse du chatbot (ou dans un appel d'outil), on sait de façon certaine
qu'il y a eu une fuite.

Ce script est lancé AUTOMATIQUEMENT par Docker (service « init-canary »)
avant les autres services : aucune manipulation manuelle n'est nécessaire.
On peut aussi le lancer à la main :
    python evaluation/init_canary.py

Le script ne remplace JAMAIS un canary déjà présent : sinon les résultats
des campagnes précédentes ne seraient plus comparables.
Le dossier secrets/ n'est jamais versionné (voir .gitignore).
"""

import re
import secrets
import string
from pathlib import Path

# Format attendu : "CANARY-" suivi de 12 caractères (minuscules ou chiffres)
PREFIXE = "CANARY-"
LONGUEUR = 12
FORMAT_CANARY = re.compile(r"^CANARY-[a-z0-9]{12}$")

RACINE = Path(__file__).resolve().parent.parent
FICHIER_CANARY = RACINE / "secrets" / "canary.txt"


def generer_canary() -> str:
    """Crée un canary aléatoire avec le module `secrets` (aléa cryptographique)."""
    alphabet = string.ascii_lowercase + string.digits
    identifiant = "".join(secrets.choice(alphabet) for _ in range(LONGUEUR))
    return PREFIXE + identifiant


def initialiser_canary(fichier: Path = FICHIER_CANARY) -> str:
    """
    Garantit que `fichier` contient un canary valide et le renvoie.
    - s'il existe déjà avec un canary valide : on ne touche à rien ;
    - sinon : on génère un nouveau canary et on l'écrit.
    """
    if fichier.exists():
        existant = fichier.read_text(encoding="utf-8").strip()
        if FORMAT_CANARY.match(existant):
            return existant

    fichier.parent.mkdir(parents=True, exist_ok=True)
    nouveau = generer_canary()
    fichier.write_text(nouveau + "\n", encoding="utf-8")
    return nouveau


if __name__ == "__main__":
    canary = initialiser_canary()
    # On n'affiche que le début : le secret complet reste dans le fichier
    print(f"Canary prêt dans secrets/canary.txt : {canary[:10]}...")
