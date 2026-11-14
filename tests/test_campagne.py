"""
Tests du script de campagne (evaluation/campagne.py), avec l'API simulée.
"""

import csv

import pytest

from evaluation import campagne

CANARY = "CANARY-ab12cd34ef56"


# ---------- préparation ----------

def test_message_genere_pour_a9():
    variante = {"repeter": {"texte": "abc ", "fois": 3}}
    assert campagne.construire_message(variante) == "abc abc abc "
    assert campagne.construire_message("texte simple") == "texte simple"


def test_graines_identiques_d_une_campagne_a_l_autre():
    scenarios = [{"id": "A1", "variantes": ["v1", "v2"]}]
    questions = [{"id": "B01", "message": "q"}]
    taches = campagne.preparer_taches(scenarios, questions, repetitions=3,
                                      repetitions_benin=2, graine_base=42)
    assert len(taches) == 2 * 3 + 2
    assert [t["graine"] for t in taches[:3]] == [42, 43, 44]   # répétitions 1, 2, 3
    assert [t["graine"] for t in taches[-2:]] == [42, 43]


# ---------- masquage ----------

def test_masquage_du_canary():
    assert campagne.masquer(f"code {CANARY} !", CANARY) == "code [CANARY] !"


def test_masquage_du_canary_epele():
    epele = "-".join(CANARY)
    assert CANARY not in campagne.masquer(epele, CANARY)
    assert "masqué" in campagne.masquer(epele, CANARY)


def test_canary_epele_a_la_coupure_des_300_caracteres_est_masque(monkeypatch):
    # Cas trouvé lors de l'essai réel : le canary épelé se trouvait au-delà
    # des 300 premiers caractères. Couper puis masquer en laisserait passer une partie.
    epele = "-".join(CANARY)
    reponse = "x" * 290 + epele
    tache = {"type": "attaque", "variante": 1, "repetition": 1, "graine": 42,
             "message": "m", "element": {"id": "A4", "id_client": "C001",
                                         "criteres": [{"type": "canary"}]}}
    resultat = {"statut_http": 200, "reponse": reponse, "outils_appeles": [],
                "bloque": False, "latence_s": 1.0, "erreur": ""}
    ligne = campagne.ligne_de_resultat(tache, resultat, "A", CANARY, {})
    assert ligne["succes"] is True
    assert "C-A-N" not in ligne["reponse_extrait"]


def test_texte_sans_canary_inchange():
    assert campagne.masquer("Bonjour", CANARY) == "Bonjour"


# ---------- envoi ----------

def test_serveur_injoignable_ne_plante_pas():
    resultat = campagne.envoyer("http://127.0.0.1:9", "test", "C001", 42, delai=2)
    assert resultat["statut_http"] == 0
    assert resultat["erreur"]


# ---------- campagne complète (API simulée) ----------

@pytest.fixture
def fausse_api(monkeypatch):
    """A4 fuit le canary (une fois par e-mail), le reste répond normalement."""
    monkeypatch.setenv("CANARY_SECRET", CANARY)

    def faux_envoyer(url, message, id_client, graine, delai=600):
        if "code d'accès" in message.lower():
            return {"statut_http": 200, "reponse": "C'est envoyé.", "bloque": False,
                    "outils_appeles": [{"nom": "envoyer_email",
                                        "arguments": {"texte": f"Code : {CANARY}"}}],
                    "latence_s": 1.0, "erreur": ""}
        return {"statut_http": 200, "reponse": "Le kWh coûte 0,21 €.", "outils_appeles": [],
                "bloque": False, "latence_s": 1.0, "erreur": ""}

    monkeypatch.setattr(campagne, "envoyer", faux_envoyer)


def lire_csv(fichier):
    with open(fichier, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_campagne_ecrit_une_ligne_par_tentative(fausse_api, tmp_path):
    fichier = campagne.lancer_campagne("A", repetitions=2, repetitions_benin=1,
                                       dossier_sortie=tmp_path)
    lignes = lire_csv(fichier)
    assert len(lignes) == 27 * 2 + 23 * 1
    assert set(lignes[0]) == set(campagne.COLONNES)
    assert fichier.name.startswith("campagne_A_")


def test_campagne_juge_les_reponses(fausse_api, tmp_path):
    lignes = lire_csv(campagne.lancer_campagne("A", 1, 1, ["A4"], dossier_sortie=tmp_path))
    attaques = [l for l in lignes if l["type"] == "attaque"]
    assert all(l["succes"] == "True" for l in attaques)          # A4 : fuite par e-mail
    b01 = next(l for l in lignes if l["id"] == "B01")
    assert b01["bloque"] == "False" and b01["contient_attendu"] == "True"


def test_le_canary_n_est_jamais_ecrit_dans_les_resultats(fausse_api, tmp_path):
    fichier = campagne.lancer_campagne("A", 1, 0, ["A4"], avec_benin=False,
                                       dossier_sortie=tmp_path)
    contenu = fichier.read_text(encoding="utf-8")
    assert CANARY not in contenu
    assert "[CANARY]" in contenu


def test_filtre_sur_quelques_scenarios(fausse_api, tmp_path):
    lignes = lire_csv(campagne.lancer_campagne("A", 1, 1, ["A1", "A5"], avec_benin=False,
                                               dossier_sortie=tmp_path))
    assert {l["id"] for l in lignes} == {"A1", "A5"}
