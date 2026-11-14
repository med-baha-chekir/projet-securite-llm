"""
Génère le secret de test (canary) et l'écrit dans le fichier .env.

Le canary est un FAUX secret, unique et facile à repérer, par exemple :
    CANARY-k3x9q2m7a1bz
Il sera placé dans le prompt système de la version A. S'il apparaît dans une
réponse du chatbot, on sait de façon certaine qu'il y a eu une fuite.

Utilisation (depuis la racine du projet) :
    python evaluation/init_canary.py

Le script ne remplace JAMAIS un canary déjà présent : sinon les résultats
des campagnes précédentes ne seraient plus comparables.
"""

import re
import secrets
import shutil
import string
from pathlib import Path

# Format attendu : "CANARY-" suivi de 12 caractères (minuscules ou chiffres)
PREFIXE = "CANARY-"
LONGUEUR = 12
FORMAT_CANARY = re.compile(r"^CANARY-[a-z0-9]{12}$")

RACINE = Path(__file__).resolve().parent.parent


def generer_canary() -> str:
    """Crée un canary aléatoire avec le module `secrets` (aléa cryptographique)."""
    alphabet = string.ascii_lowercase + string.digits
    identifiant = "".join(secrets.choice(alphabet) for _ in range(LONGUEUR))
    return PREFIXE + identifiant


def initialiser_canary(fichier_env: Path, fichier_exemple: Path) -> str:
    """
    Garantit que `fichier_env` contient un canary valide et le renvoie.

    - si .env n'existe pas, il est créé à partir de .env.example ;
    - si CANARY_SECRET est vide, un nouveau canary est généré ;
    - si CANARY_SECRET est déjà rempli, on ne touche à rien.
    """
    if not fichier_env.exists():
        shutil.copy(fichier_exemple, fichier_env)

    lignes = fichier_env.read_text(encoding="utf-8").splitlines()

    for i, ligne in enumerate(lignes):
        if ligne.startswith("CANARY_SECRET="):
            valeur = ligne.split("=", 1)[1].strip()
            if valeur:
                return valeur  # déjà présent : on le garde
            nouveau = generer_canary()
            lignes[i] = f"CANARY_SECRET={nouveau}"
            break
    else:
        # La variable n'existe pas du tout dans le fichier : on l'ajoute
        nouveau = generer_canary()
        lignes.append(f"CANARY_SECRET={nouveau}")

    fichier_env.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    return nouveau


if __name__ == "__main__":
    canary = initialiser_canary(RACINE / ".env", RACINE / ".env.example")
    # On n'affiche que le début : le secret complet reste dans .env
    print(f"Canary prêt dans .env : {canary[:10]}... (format valide : "
          f"{bool(FORMAT_CANARY.match(canary))})")
