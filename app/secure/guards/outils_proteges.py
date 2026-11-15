"""
Protection n° 5 : OUTILS EN MOINDRE PRIVILÈGE + CONFIRMATION (scénarios A6, A8).

Dans la version A, les outils font tout ce que le modèle demande. Or le modèle
peut être manipulé : c'est donc au CODE de vérifier chaque action, pas au modèle.

Règle générale : un outil n'agit QUE pour le client connecté.

  consulter_fiche_client   seulement la fiche du client connecté ;
  creer_remboursement      seulement pour le client connecté, et seulement son
                           AVOIR (solde négatif), jamais un montant supérieur ;
  envoyer_email            seulement vers l'adresse e-mail enregistrée du client
                           connecté (liste blanche d'un seul destinataire).

Un appel refusé renvoie {"refuse": "raison"} : l'outil n'a rien fait, le modèle
en est informé, une alerte est écrite dans le journal.

CONFIRMATION (deuxième barrière, interrupteur séparé) : une action sensible
(remboursement, e-mail) qui a passé les contrôles n'est PAS exécutée tout de
suite. Elle est mise en attente, et le client doit la confirmer lui-même par
POST /confirmer. Ainsi, même une action « autorisée » ne peut pas être
déclenchée par une injection à l'insu du client.

LIMITES (à dire dans le rapport) :
  - l'identité du client connecté est seulement DÉCLARÉE par l'interface (pas de
    vraie authentification) : ces contrôles empêchent un client d'agir sur un
    AUTRE compte, pas un attaquant qui se déclare directement comme la victime ;
  - les actions en attente sont gardées en mémoire : elles sont perdues au
    redémarrage du service.
"""

import uuid

REFUS_AUTRE_CLIENT = "action autorisée uniquement pour le client connecté"

# Actions en attente de confirmation : {id_action: {"id_client", "nom", "arguments"}}
EN_ATTENTE: dict[str, dict] = {}
MAX_EN_ATTENTE = 100   # borne la mémoire utilisée (sinon : déni de service)


def identifiant(valeur) -> str:
    return str(valeur or "").strip().upper()


def mettre_en_attente(id_client: str, nom: str, arguments: dict) -> dict:
    """Enregistre l'action sans l'exécuter. Renvoie ce qui est dit au modèle."""
    if len(EN_ATTENTE) >= MAX_EN_ATTENTE:
        EN_ATTENTE.pop(next(iter(EN_ATTENTE)))   # on oublie la plus ancienne
    id_action = uuid.uuid4().hex[:8]
    EN_ATTENTE[id_action] = {"id_client": id_client, "nom": nom, "arguments": arguments}
    return {"statut": "en attente de confirmation par le client", "id_action": id_action}


def proteger_outils(fonctions: dict, clients: dict, id_client: str, alertes: list[str],
                    confirmation: bool, en_attente: list[dict]) -> dict:
    """
    Enveloppe les outils avec les contrôles de moindre privilège.
    - clients : {id: fiche}, pour connaître l'avoir et l'e-mail du client connecté ;
    - alertes : liste de la requête, complétée à chaque refus ;
    - confirmation : si vrai, les actions sensibles sont mises en attente ;
    - en_attente : liste de la requête, complétée par les actions à confirmer.
    """
    connecte = identifiant(id_client)
    fiche = clients.get(connecte)

    def refuser(nom: str, raison: str) -> dict:
        alertes.append(f"outil {nom} refusé: {raison}")
        return {"refuse": raison}

    def executer(nom: str, arguments: dict) -> dict:
        """Action sensible autorisée : exécutée, ou mise en attente de confirmation."""
        if not confirmation:
            return fonctions[nom](**arguments)
        resultat = mettre_en_attente(connecte, nom, arguments)
        en_attente.append({"id_action": resultat["id_action"], "nom": nom, "arguments": arguments})
        return resultat

    def consulter_fiche_client(id_client=None, **_):
        if fiche is None or identifiant(id_client) != connecte:
            return refuser("consulter_fiche_client", REFUS_AUTRE_CLIENT)
        return fonctions["consulter_fiche_client"](id_client=connecte)

    def creer_remboursement(id_client=None, montant=None, **_):
        if fiche is None or identifiant(id_client) != connecte:
            return refuser("creer_remboursement", REFUS_AUTRE_CLIENT)
        try:
            montant = float(str(montant).replace(",", "."))
        except ValueError:
            return refuser("creer_remboursement", "montant illisible")
        avoir = max(0.0, -fiche.get("solde_euros", 0))   # avoir = solde négatif
        if montant <= 0 or montant > avoir + 0.01:
            return refuser("creer_remboursement",
                           f"montant refusé : l'avoir remboursable est de {avoir:.2f} euros")
        return executer("creer_remboursement", {"id_client": connecte, "montant": montant})

    def envoyer_email(destinataire=None, texte="", **_):
        adresse = (fiche or {}).get("email", "").lower()
        if not adresse or str(destinataire or "").strip().lower() != adresse:
            return refuser("envoyer_email",
                           "destinataire refusé : seule l'adresse enregistrée du client est autorisée")
        return executer("envoyer_email", {"destinataire": adresse, "texte": str(texte)})

    return {"consulter_fiche_client": consulter_fiche_client,
            "creer_remboursement": creer_remboursement,
            "envoyer_email": envoyer_email}


def confirmer(id_action: str, id_client: str, fonctions: dict) -> dict:
    """
    Exécute une action en attente, à la demande du client.
    Seul le client qui est à l'origine de l'action peut la confirmer, et une seule fois.
    """
    action = EN_ATTENTE.get(id_action)
    if action is None or action["id_client"] != identifiant(id_client):
        return {"refuse": "action inconnue ou déjà traitée"}
    del EN_ATTENTE[id_action]
    return fonctions[action["nom"]](**action["arguments"])
