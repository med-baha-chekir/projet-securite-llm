"""
Protection n° 8 : LIMITE DE DÉBIT et TAILLE MAXIMALE DE RÉPONSE (scénario A9,
OWASP LLM10 « consommation non bornée »).

Un appel au modèle coûte cher (ici : plus de 10 secondes de carte graphique).
Sans limite, un seul utilisateur peut saturer le service (déni de service), ou
faire exploser la facture si le modèle est payé à l'usage.

  1. LIMITE DE DÉBIT, par client : principe du « seau à jetons ». Chaque client
     a un seau de CAPACITE jetons ; une requête consomme un jeton ; le seau se
     remplit d'un jeton toutes les RECHARGE_S secondes. Un client peut donc
     envoyer une petite rafale, puis doit ralentir. Seau vide : la requête est
     refusée (code HTTP 429 « trop de requêtes ») sans appeler le modèle ;

  2. TAILLE MAXIMALE DE RÉPONSE : l'option « num_predict » d'Ollama arrête la
     génération après MAX_TOKENS_REPONSE tokens (un token = environ 3 à 4
     caractères). Une demande de « 20 conseils par pièce » ne monopolise plus
     le modèle.

La taille maximale du message d'ENTRÉE est dans le filtre d'entrée.

Choix : limiteur écrit à la main plutôt que la bibliothèque slowapi. slowapi
compte par adresse IP ; dans le labo, toutes les requêtes viennent de la même
adresse (le conteneur de l'interface). On compte donc par client connecté.

LIMITES (à dire dans le rapport) :
  - l'identité du client est seulement déclarée : un attaquant peut changer
    d'identifiant à chaque requête pour contourner la limite. Avec une vraie
    authentification, on compterait par compte ET par adresse IP ;
  - les compteurs sont en mémoire : remis à zéro au redémarrage, et non partagés
    si le service tournait sur plusieurs machines.
"""

import os
import threading
import time

CAPACITE = int(os.environ.get("DEBIT_CAPACITE", "10"))            # rafale autorisée
RECHARGE_S = float(os.environ.get("DEBIT_RECHARGE_S", "3"))       # 1 jeton toutes les 3 s = 20 / min
MAX_TOKENS_REPONSE = int(os.environ.get("MAX_TOKENS_REPONSE", "600"))   # environ 2 000 caractères
MAX_CLIENTS_SUIVIS = 1000   # borne la mémoire du limiteur lui-même


class LimiteurDebit:
    """Seau à jetons par client. « horloge » est remplaçable pour les tests."""

    def __init__(self, capacite: int = CAPACITE, recharge_s: float = RECHARGE_S,
                 horloge=time.monotonic):
        self.capacite, self.recharge_s, self.horloge = capacite, recharge_s, horloge
        self.seaux: dict[str, tuple[float, float]] = {}   # client -> (jetons, heure de la dernière mise à jour)
        self.verrou = threading.Lock()   # plusieurs requêtes arrivent en même temps (rafale)

    def autoriser(self, client: str) -> bool:
        """Consomme un jeton du client. Renvoie False si son seau est vide."""
        maintenant = self.horloge()
        with self.verrou:
            if client not in self.seaux and len(self.seaux) >= MAX_CLIENTS_SUIVIS:
                self.seaux.pop(next(iter(self.seaux)))   # on oublie le plus ancien
            jetons, derniere = self.seaux.get(client, (float(self.capacite), maintenant))
            # Jetons regagnés depuis la dernière requête, sans dépasser la capacité
            jetons = min(self.capacite, jetons + (maintenant - derniere) / self.recharge_s)
            if jetons < 1:
                self.seaux[client] = (jetons, maintenant)
                return False
            self.seaux[client] = (jetons - 1, maintenant)
            return True
