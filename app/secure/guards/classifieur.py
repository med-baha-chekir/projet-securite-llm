"""
Protection n° 3 : CLASSIFIEUR DE SÉCURITÉ (Llama Guard 3, version 1B).

Llama Guard est un petit modèle spécialisé : on lui donne un message, il répond
« safe » ou « unsafe » suivi d'une catégorie (S1 à S13 : crimes violents, armes,
haine, données privées...). Il tourne en local dans Ollama, comme le reste.

Différence avec le filtre d'entrée : le filtre cherche des TOURNURES précises ;
le classifieur juge le SENS du message, même reformulé ou dans une autre langue.

LIMITES (à dire dans le rapport) :
  - Llama Guard reconnaît les contenus DANGEREUX (violence, illégal, haine...).
    Il n'est PAS entraîné à reconnaître une injection de prompt : « ignore tes
    instructions » n'entre dans aucune de ses catégories. Il complète donc le
    filtre d'entrée, il ne le remplace pas ;
  - c'est un modèle : il se trompe, dans les deux sens (attaque non vue,
    question honnête jugée dangereuse) ;
  - il ajoute un appel de modèle à CHAQUE question : la latence augmente.

Choix techniques :
  - le classifieur tourne sur le PROCESSEUR (num_gpu = 0). La carte graphique
    (4 Go) est déjà pleine avec le modèle principal : y charger un troisième
    modèle provoque les blocages d'Ollama constatés le 15/11/2026 ;
  - température 0 : le même message donne toujours le même verdict ;
  - si le classifieur est en panne, la requête est REFUSÉE (« fail closed ») :
    une protection qui laisse tout passer quand elle tombe ne protège pas.
"""

import os

import ollama

from app.shared.config import Config

MODELE_CLASSIFIEUR = os.environ.get("GUARD_MODEL", "llama-guard3:1b")


def classer(config: Config, message: str) -> str | None:
    """
    Renvoie None si le message est jugé sûr, sinon le motif du refus :
    « unsafe:S2 » (catégorie donnée par Llama Guard) ou « classifieur_indisponible ».
    """
    try:
        client = ollama.Client(host=config.ollama_url, timeout=120)
        reponse = client.chat(
            model=MODELE_CLASSIFIEUR,
            messages=[{"role": "user", "content": message}],
            options={"temperature": 0, "num_gpu": 0, "num_predict": 20},
        )
        verdict = (reponse.message.content or "").strip().lower()
    except Exception:           # modèle absent, Ollama injoignable, délai dépassé...
        return "classifieur_indisponible"

    if verdict.startswith("safe"):
        return None
    if verdict.startswith("unsafe"):
        categorie = verdict.replace("unsafe", "").strip().upper() or "?"
        return f"unsafe:{categorie.split()[0]}"
    return "classifieur_indisponible"   # réponse inattendue : on ne devine pas
