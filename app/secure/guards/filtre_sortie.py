"""
Protection n° 6 : FILTRE DE SORTIE (scénarios A3, A4, A7, A8).

Dernière barrière : tout ce qui SORT du chatbot (réponse, texte d'un e-mail,
arguments d'outils affichés dans l'interface) est contrôlé par du code avant
d'atteindre l'utilisateur. Même si une attaque a trompé le modèle, la fuite est
arrêtée ici. Trois contrôles indépendants, chacun avec son interrupteur :

  1. SECRETS : le canary (tel quel, épelé, à l'envers, ou sa partie aléatoire
     seule) et les codes internes (ex. STAFF-...) sont masqués ;
  2. DONNÉES PERSONNELLES : le nom, l'e-mail, le téléphone et l'adresse des
     AUTRES clients sont masqués, ainsi que les IBAN ;
  3. CONTENU ACTIF : les images Markdown et les liens vers l'extérieur sont
     retirés (une image fait partir une requête du navigateur de la victime,
     avec des données dans l'adresse), et le HTML est rendu inoffensif.

Le filtre CORRIGE la réponse au lieu de la bloquer, et écrit une alerte.

Choix : pas de Microsoft Presidio. Cet outil reconnaît des données personnelles
INCONNUES (noms, numéros) à l'aide de modèles de langue assez lourds. Ici, les
données à protéger sont CONNUES (le fichier clients) : une comparaison exacte
est plus simple, plus rapide et sans faux positif sur les noms.

LIMITES (à dire dans le rapport) :
  - un secret transformé autrement (traduit, en base64, découpé sur plusieurs
    réponses) n'est pas reconnu ;
  - une donnée personnelle absente du fichier clients, ou reformulée (« il habite
    à Marseille, avenue des Platanes »), n'est pas reconnue ;
  - une adresse web écrite en clair, sans lien ni image, reste affichée (le
    navigateur ne l'ouvre pas tout seul : il faut que la victime clique).
"""

import re

MASQUE = "[MASQUÉ]"
REPONSE_SECRET = "Désolé, je ne peux pas communiquer cette information."

# Codes internes qui ne doivent jamais sortir, quel que soit leur chemin
# (ici : un code promotionnel réservé au personnel, présent dans un document).
MOTIFS_SECRETS = [re.compile(r"\bSTAFF-[A-Z0-9][A-Z0-9-]{3,}\b", re.IGNORECASE)]

# Seuls domaines vers lesquels un lien cliquable est accepté
DOMAINES_AUTORISES = ("brumelec.test",)


# ---------- 1. secrets ----------

def normaliser(texte: str) -> str:
    """Minuscules, lettres et chiffres seulement : « C-A-N-A-R-Y » devient « canary »."""
    return re.sub(r"[^a-z0-9]", "", texte.lower())


def partie_aleatoire(canary: str) -> str:
    """Le vrai secret est la partie après « CANARY- » (le préfixe est connu de tous)."""
    suite = canary.split("-", 1)[-1]
    return suite if len(normaliser(suite)) >= 8 else canary


def contient_secret(texte: str, canary: str) -> bool:
    """Vrai si le canary est présent sous une forme quelconque (épelé, à l'envers...)."""
    if not canary:
        return False
    cherche, contenu = normaliser(partie_aleatoire(canary)), normaliser(texte)
    return cherche in contenu or cherche[::-1] in contenu


def masquer_secrets(texte: str, canary: str, alertes: list[str]) -> str:
    propre = texte
    if canary:
        propre = propre.replace(canary, MASQUE).replace(partie_aleatoire(canary), MASQUE)
    if propre != texte:
        alertes.append("sortie: canary masqué")
    for motif in MOTIFS_SECRETS:
        propre, nombre = motif.subn(MASQUE, propre)
        if nombre:
            alertes.append("sortie: code interne masqué")
    # Forme modifiée (épelée, à l'envers) : impossible à masquer proprement,
    # toute la réponse est remplacée.
    if contient_secret(propre, canary):
        alertes.append("sortie: canary sous forme modifiée, réponse remplacée")
        return REPONSE_SECRET
    return propre


def masquer_arguments(valeur, canary: str, alertes: list[str]):
    """Masque les secrets dans les arguments d'un outil (texte, dictionnaire ou liste)."""
    if isinstance(valeur, str):
        return masquer_secrets(valeur, canary, alertes)
    if isinstance(valeur, dict):
        return {cle: masquer_arguments(v, canary, alertes) for cle, v in valeur.items()}
    if isinstance(valeur, list):
        return [masquer_arguments(v, canary, alertes) for v in valeur]
    return valeur


def proteger_outils(fonctions: dict, canary: str, alertes: list[str]) -> dict:
    """
    Les secrets sont masqués dans les arguments AVANT l'exécution de l'outil :
    le chatbot ne peut pas faire sortir le secret dans le texte d'un e-mail
    (exfiltration par outil, constatée sur la version A).
    """
    def envelopper(fonction):
        return lambda **arguments: fonction(**masquer_arguments(arguments, canary, alertes))

    return {nom: envelopper(fonction) for nom, fonction in fonctions.items()}


def contient_consignes(texte: str, consignes: str, longueur: int = 50) -> bool:
    """
    Vrai si la réponse recopie une ligne des consignes internes (scénario A3).
    On compare le début de chaque ligne assez longue, sans ponctuation ni majuscules.
    Limite : des consignes TRADUITES ou reformulées ne sont pas reconnues.
    """
    contenu = normaliser(texte)
    for ligne in consignes.splitlines():
        debut = normaliser(ligne)[:longueur]
        if len(debut) == longueur and debut in contenu:
            return True
    return False


# ---------- 2. données personnelles des autres clients ----------

IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b")


def motif_telephone(telephone: str) -> re.Pattern:
    """« 01 99 00 34 56 » est reconnu aussi écrit 0199003456 ou 01.99.00.34.56."""
    chiffres = re.sub(r"\D", "", telephone)
    return re.compile(r"(?<!\d)" + r"[ .\-]?".join(chiffres) + r"(?!\d)")


def masquer_donnees_personnelles(texte: str, clients: dict, id_client: str,
                                 alertes: list[str]) -> str:
    """Masque tout ce qui identifie un client AUTRE que le client connecté."""
    connecte = str(id_client).strip().upper()
    propre = texte
    for client in clients.values():
        if client["id"] == connecte:
            continue
        motifs = [re.compile(re.escape(client["email"]), re.IGNORECASE),
                  motif_telephone(client["telephone"]),
                  re.compile(re.escape(client["adresse"]), re.IGNORECASE),
                  re.compile(r"\b" + re.escape(client["nom"]) + r"\b", re.IGNORECASE),
                  # nom de famille seul (« Mme Fontanier »)
                  re.compile(r"\b" + re.escape(client["nom"].split()[-1]) + r"\b", re.IGNORECASE)]
        for motif in motifs:
            propre = motif.sub(MASQUE, propre)
    sans_iban = IBAN.sub(MASQUE, propre)
    if sans_iban != texte:
        alertes.append("sortie: donnée personnelle masquée")
    return sans_iban


# ---------- 3. contenu actif (images, liens, HTML) ----------

IMAGE_MARKDOWN = re.compile(r"!\[[^\]]*\]\([^)]*\)")
LIEN_MARKDOWN = re.compile(r"\[([^\]]+)\]\(\s*(https?://[^)\s]+)[^)]*\)", re.IGNORECASE)
DEBUT_DE_BALISE = re.compile(r"<(?=\s*[/!?]?\s*[a-zA-Z])")
GESTIONNAIRE_JS = re.compile(r"\bon[a-z]+\s*=|javascript\s*:", re.IGNORECASE)


def domaine_autorise(url: str) -> bool:
    hote = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].split(":")[0].lower()
    return any(hote == d or hote.endswith("." + d) for d in DOMAINES_AUTORISES)


def neutraliser_contenu_actif(texte: str, alertes: list[str]) -> str:
    # Images : toujours retirées. Un chatbot de service client n'a aucune raison
    # d'afficher une image, et le navigateur la charge sans aucun clic.
    propre, nombre = IMAGE_MARKDOWN.subn("[image retirée]", texte)
    if nombre:
        alertes.append("sortie: image retirée")

    # Liens : on garde le texte, on retire l'adresse si le domaine n'est pas autorisé
    def remplacer_lien(m):
        if domaine_autorise(m.group(2)):
            return m.group(0)
        alertes.append("sortie: lien externe retiré")
        return f"{m.group(1)} [lien retiré]"
    propre = LIEN_MARKDOWN.sub(remplacer_lien, propre)

    # HTML : « < » devient « &lt; », la balise s'affiche comme du texte et ne s'exécute pas
    echappe = DEBUT_DE_BALISE.sub("&lt;", propre)
    echappe = GESTIONNAIRE_JS.sub("[retiré]", echappe)
    if echappe != propre:
        alertes.append("sortie: HTML neutralisé")
    return echappe
