"""
Protection n° 4 : NETTOYAGE et DÉLIMITATION des données externes (scénario A5).

Problème (injection INDIRECTE) : le texte d'un document du RAG, ou le résultat
d'un outil (ex. la note d'une fiche client), est ajouté à ce que lit le modèle.
Si ce texte contient « ignore tes instructions... », le modèle peut obéir : il ne
fait pas la différence entre une DONNÉE et un ORDRE. L'attaquant n'a même pas
besoin de parler au chatbot, il lui suffit de modifier un document.

Deux défenses complémentaires :
  1. NETTOYAGE (du code, fiable sur ce qu'il sait reconnaître) :
     - les commentaires HTML « <!-- ... --> » sont supprimés : un humain qui lit
       le document ne les voit pas, c'est la cachette classique d'une injection ;
     - les caractères invisibles sont retirés ;
     - les paragraphes qui ressemblent à une injection (mêmes signatures que le
       filtre d'entrée) sont supprimés ;
  2. DÉLIMITATION (une aide pour le modèle, pas une garantie) : chaque passage est
     entouré de balises <document> ... </document>, et le prompt précise que ce
     qui se trouve entre ces balises est une information, jamais un ordre.

Les résultats des OUTILS reçoivent le même nettoyage avant d'être rendus au modèle.

LIMITES (à dire dans le rapport) :
  - une injection en texte visible et reformulée échappe aux signatures ; il ne
    reste alors que la délimitation, que le modèle peut ne pas respecter ;
  - le nettoyage peut supprimer un paragraphe légitime qui ressemble à une
    consigne (faux positif sur un document).
"""

import re

from app.secure.guards import filtre_entree

COMMENTAIRE_HTML = re.compile(r"<!--.*?-->", re.DOTALL)
# Commentaire jamais refermé : tout ce qui suit « <!-- » est caché aussi
COMMENTAIRE_OUVERT = re.compile(r"<!--.*", re.DOTALL)
# Un document ne doit pas pouvoir « fermer » lui-même sa balise de délimitation
FAUSSE_BALISE = re.compile(r"</?\s*document\b[^>]*>", re.IGNORECASE)

# Signatures cherchées dans les documents : celles du filtre d'entrée, sauf
# « donnees_internes » (un document interne a le droit de parler d'informations internes).
REGLES_DOCUMENT = [(nom, motif) for nom, motif in filtre_entree.REGLES if nom != "donnees_internes"]


def nettoyer_texte(texte: str) -> tuple[str, list[str]]:
    """
    Renvoie (texte nettoyé, liste des anomalies trouvées).
    La liste sert à écrire une ALERTE dans le journal : un document piégé est un
    incident de sécurité, même si le piège a été désamorcé.
    """
    anomalies = []

    propre = COMMENTAIRE_HTML.sub("", texte)
    propre = COMMENTAIRE_OUVERT.sub("", propre)
    if propre != texte:
        anomalies.append("commentaire_cache")

    sans_invisibles = filtre_entree.nettoyer(propre)
    if sans_invisibles != propre:
        anomalies.append("caracteres_invisibles")
    propre = sans_invisibles

    if FAUSSE_BALISE.search(propre):
        anomalies.append("fausse_balise")
        propre = FAUSSE_BALISE.sub("", propre)

    # Paragraphe par paragraphe : on ne retire que le passage suspect, pas tout le document
    gardes = []
    for paragraphe in re.split(r"\n\s*\n", propre):
        simple = filtre_entree.simplifier(paragraphe)
        regle = next((nom for nom, motif in REGLES_DOCUMENT if motif.search(simple)), None)
        if regle:
            anomalies.append(f"injection:{regle}")
        else:
            gardes.append(paragraphe)

    return "\n\n".join(gardes).strip(), anomalies


def nettoyer_passages(passages: list[dict]) -> tuple[list[dict], list[str]]:
    """Nettoie les passages du RAG. Renvoie (passages nettoyés, alertes « source: anomalie »)."""
    propres, alertes = [], []
    for passage in passages:
        texte, anomalies = nettoyer_texte(passage["texte"])
        propres.append({**passage, "texte": texte})
        alertes += [f"document {passage['source']}: {a}" for a in anomalies]
    return propres, alertes


def delimiter(passages: list[dict]) -> str:
    """Entoure chaque passage de balises, avec sa source."""
    return "\n\n".join(f'<document source="{p["source"]}">\n{p["texte"]}\n</document>'
                       for p in passages if p["texte"])


def nettoyer_resultat(valeur, anomalies: list[str]):
    """Nettoie tous les textes d'un résultat d'outil (dictionnaire, liste ou texte)."""
    if isinstance(valeur, str):
        texte, trouvees = nettoyer_texte(valeur)
        anomalies += trouvees
        return texte
    if isinstance(valeur, dict):
        return {cle: nettoyer_resultat(v, anomalies) for cle, v in valeur.items()}
    if isinstance(valeur, list):
        return [nettoyer_resultat(v, anomalies) for v in valeur]
    return valeur   # nombre, booléen, None : rien à nettoyer


def proteger_outils(fonctions: dict, alertes: list[str]) -> dict:
    """
    Enveloppe chaque outil : son résultat est nettoyé avant d'être rendu au modèle.
    Les anomalies trouvées sont ajoutées à la liste « alertes » de la requête.
    """
    def envelopper(nom, fonction):
        def outil_protege(**arguments):
            anomalies = []
            resultat = nettoyer_resultat(fonction(**arguments), anomalies)
            alertes.extend(f"outil {nom}: {a}" for a in anomalies)
            return resultat
        return outil_protege

    return {nom: envelopper(nom, fonction) for nom, fonction in fonctions.items()}
