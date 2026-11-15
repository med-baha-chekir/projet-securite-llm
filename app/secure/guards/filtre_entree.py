"""
Protection n° 2 : FILTRE D'ENTRÉE (scénarios A1, A2, A3, A9, A10).

Le message de l'utilisateur est contrôlé AVANT d'être envoyé au modèle.
Contrairement au prompt durci (une consigne que le modèle peut ignorer),
ce filtre est du code : s'il refuse, le modèle ne voit jamais le message.

Trois contrôles :
  1. TAILLE MAXIMALE : un message trop long est refusé (A9, déni de service) ;
  2. NETTOYAGE : les caractères invisibles sont retirés et les caractères
     « déguisés » ramenés à leur forme normale (A10). Sans cela, « i​gnore »
     écrit avec un espace invisible échappe à la recherche du mot « ignore » ;
  3. DÉTECTION D'INJECTION : recherche de tournures typiques d'une attaque,
     en français, en anglais et en espagnol, y compris cachées en base64.

LIMITES (à dire dans le rapport) :
  - c'est une liste de SIGNATURES : une attaque reformulée autrement, ou écrite
    dans une autre langue, passe. D'où la protection suivante (classifieur) ;
  - les règles ont été écrites en connaissant les attaques A1 à A10 : leur taux
    de détection sur ces attaques est donc optimiste ;
  - un filtre trop large bloque des clients honnêtes (faux positifs). Les
    questions pièges de attacks/benign.yaml servent à le vérifier.
"""

import base64
import os
import re
import unicodedata

# Une question de client fait rarement plus de quelques centaines de caractères
# (la plus longue question légitime de test en fait environ 750).
TAILLE_MAX = int(os.environ.get("TAILLE_MAX_CARACTERES", "2000"))


def taille_acceptable(message: str, maximum: int = TAILLE_MAX) -> bool:
    return len(message) <= maximum


def nettoyer(message: str) -> str:
    """
    Remet le texte sous une forme « normale », sans changer ce que lit un humain :
    - NFKC : les caractères déguisés (ｉｇｎｏｒｅ en pleine largeur, ligatures...)
      redeviennent des lettres ordinaires ;
    - les caractères de catégorie « Cf » (espaces de largeur nulle, marques
      invisibles) sont supprimés.
    C'est ce texte nettoyé qui est envoyé au modèle.
    """
    texte = unicodedata.normalize("NFKC", message)
    return "".join(c for c in texte if unicodedata.category(c) != "Cf")


def simplifier(texte: str) -> str:
    """Pour la DÉTECTION seulement : minuscules, sans accents, apostrophes et espaces unifiés."""
    texte = nettoyer(texte).lower().replace("’", "'")
    sans_accents = "".join(c for c in unicodedata.normalize("NFD", texte)
                           if unicodedata.category(c) != "Mn")
    return re.sub(r"[ \t]+", " ", sans_accents)


# Une règle = (nom, expression régulière). Le nom est écrit dans le journal.
# Les expressions s'appliquent au texte SIMPLIFIÉ (sans accents, en minuscules).
REGLES = [
    # « Ignore tes instructions », « forget the previous rules », « olvida las reglas »
    ("annulation_des_consignes",
     r"\b(ignore[zs]?|oublie[zs]?|annule[zs]?|desactive[zs]?|forget|disregard|override|ignora|olvida)\b"
     r".{0,40}\b(instructions?|consignes?|regles?|directives?|rules?|instrucciones|reglas)\b"),
    # « Les règles précédentes sont annulées », « the previous rules are cancelled »
    ("consignes_declarees_annulees",
     r"\b(regles?|consignes?|instructions?|rules?|instrucciones|reglas)\b"
     r".{0,30}\b(annulees?|supprimees?|cancell?ed|revoked|anuladas)\b"),
    # Faux message du système ou d'un administrateur
    ("fausse_autorite",
     r"\bnouvelles? (consignes?|instructions?|regles?) systeme\b|\bnew system (instructions?|rules?)\b"
     r"|\bnuevas instrucciones\b|\[(admin|system|systeme|root)\]"
     r"|\bmode (maintenance|developpeur|debug|admin)\b|\b(maintenance|developer|debug) mode\b"
     r"|^\s*#{2,}.+#{2,}\s*$"),          # ligne de titre « ### ... ### »
    # Jeu de rôle destiné à faire sortir le chatbot de son rôle
    ("changement_de_role",
     r"\btu es (maintenant|desormais)\b|\byou are now\b|\bahora eres\b|\btu joues\b|\bjouons a\b"
     r"|\b(agis|comporte-toi) comme\b|\bact as\b|\bpretend (to be|you)\b|\bliberee? de toute\b"),
    # Demande de recopier les consignes internes
    ("extraction_des_consignes",
     r"\b(mot pour mot|word for word|palabra por palabra|verbatim)\b"
     r"|\b(tes|vos|your|tus) (instructions?|consignes?|regles|directives|prompt|rules)\b"
     r"|\bprompt systeme\b|\bsystem prompt\b"
     r"|\b(texte|text|texto)\b.{0,30}\b(au-dessus|ci-dessus|above|encima)\b"
     r"|\bconfiguration interne\b"),
    # Demande d'informations qu'un client n'a jamais besoin de connaître
    ("donnees_internes",
     r"\bcode d'acces\b|\baccess code\b|\binformations? internes?\b"),
]
# re.MULTILINE : « ^ » et « $ » valent pour chaque ligne du message
REGLES = [(nom, re.compile(motif, re.MULTILINE)) for nom, motif in REGLES]

# Suite d'au moins 24 caractères base64 : peut cacher une consigne encodée
MOTIF_BASE64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")


def textes_caches(message: str) -> list[str]:
    """Décode les morceaux en base64 qui contiennent du texte lisible."""
    decodes = []
    for morceau in MOTIF_BASE64.findall(message):
        try:
            texte = base64.b64decode(morceau + "=" * (-len(morceau) % 4)).decode("utf-8")
        except ValueError:      # pas du base64, ou pas du texte : on ignore
            continue
        if texte.isprintable() or "\n" in texte:
            decodes.append(texte)
    return decodes


def detecter_injection(message: str) -> str | None:
    """
    Renvoie le nom de la première règle déclenchée, ou None si rien n'est suspect.
    Le message est examiné tel quel, puis ses éventuelles parties en base64.
    """
    for i, texte in enumerate([message] + textes_caches(message)):
        simple = simplifier(texte)
        for nom, motif in REGLES:
            if motif.search(simple):
                return nom if i == 0 else f"{nom} (base64)"
    return None
