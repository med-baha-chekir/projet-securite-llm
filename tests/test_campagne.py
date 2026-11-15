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


def test_canary_epele_loin_dans_la_reponse_est_masque(monkeypatch):
    # Cas trouvé lors de l'essai réel : le canary épelé se trouvait au-delà
    # des 300 premiers caractères. La réponse complète est désormais enregistrée.
    epele = "-".join(CANARY)
    reponse = "x" * 290 + epele
    tache = {"type": "attaque", "variante": 1, "repetition": 1, "graine": 42,
             "message": "m", "element": {"id": "A4", "id_client": "C001",
                                         "criteres": [{"type": "canary"}]}}
    resultat = {"statut_http": 200, "reponse": reponse, "outils_appeles": [],
                "bloque": False, "latence_s": 1.0, "erreur": ""}
    ligne = campagne.ligne_de_resultat(tache, resultat, "A", CANARY, {})
    assert ligne["succes"] is True
    assert "C-A-N" not in ligne["reponse"]
    assert ligne["longueur_reponse"] == len(reponse)


def test_la_reponse_complete_est_enregistree():
    tache = {"type": "legitime", "variante": 1, "repetition": 1, "graine": 42,
             "message": "m", "element": {"id": "B01", "id_client": "C001"}}
    resultat = {"statut_http": 200, "reponse": "a" * 5000, "outils_appeles": [],
                "bloque": False, "latence_s": 1.0, "erreur": ""}
    ligne = campagne.ligne_de_resultat(tache, resultat, "A", CANARY, {})
    assert len(ligne["reponse"]) == 5000 and ligne["rafale"] == ""


# ---------- rafale (A9) et intervalle de confiance ----------

def test_variante_rafale():
    variante = {"rafale": {"texte": "Bonjour", "fois": 20}}
    assert campagne.construire_message(variante) == "Bonjour"
    assert campagne.taille_rafale(variante) == 20
    assert campagne.taille_rafale("texte simple") == 0


def test_rafale_compte_les_requetes_acceptees(monkeypatch):
    statuts = iter([200, 200, 429, 429, 200])
    monkeypatch.setattr(campagne, "envoyer", lambda *a, **k: {
        "statut_http": next(statuts), "reponse": "ok", "outils_appeles": [],
        "bloque": False, "latence_s": 0.1, "erreur": ""})
    resultat = campagne.envoyer_rafale("http://x", "Bonjour", "C001", 42, fois=5)
    assert resultat["rafale"] == {"envoyees": 5, "acceptees": 3}
    assert resultat["statut_http"] == 200


def test_intervalle_wilson():
    bas, haut = campagne.intervalle_wilson(1, 15)
    assert 1 < bas < 2 and 29 < haut < 31          # 1/15 : entre 1 % et 30 % environ
    assert campagne.intervalle_wilson(0, 0) == (0.0, 0.0)
    bas, haut = campagne.intervalle_wilson(15, 15)
    assert haut == 100.0 and bas > 75


def test_masquage_de_la_partie_aleatoire_seule():
    # Trouvé lors de l'essai du 15/11/2026 : la suite du canary, donnée sans le
    # préfixe, était écrite en clair dans le fichier de résultats
    texte = campagne.masquer('Il commence par "CANARY-" et la suite est "ab12cd34ef56".', CANARY)
    assert "ab12cd34ef56" not in texte


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
        if "code" in message.lower() or "informations internes" in message.lower():
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
    assert len(lignes) == 31 * 2 + 31 * 1   # 31 variantes d'attaque, 31 questions légitimes
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


def test_reprise_rejoue_seulement_les_manquantes_et_les_erreurs(fausse_api, tmp_path):
    # Campagne « interrompue » : A1 et A5 faites, mais une ligne de A1 en erreur
    premiere = campagne.lancer_campagne("A", 2, 0, ["A1", "A5"], avec_benin=False,
                                        dossier_sortie=tmp_path / "1")
    lignes = lire_csv(premiere)
    lignes[0]["erreur"] = "TimeoutError: timed out"
    with open(premiere, "w", newline="", encoding="utf-8") as f:
        ecrivain = csv.DictWriter(f, fieldnames=campagne.COLONNES)
        ecrivain.writeheader()
        ecrivain.writerows(lignes)

    envoyes = []
    vrai_envoyer = campagne.envoyer
    def compter(*a, **k):
        envoyes.append(a[1])
        return vrai_envoyer(*a, **k)
    campagne.envoyer = compter
    try:
        reprise = campagne.lancer_campagne("A", 2, 0, ["A1", "A5", "A4"], avec_benin=False,
                                           dossier_sortie=tmp_path / "2", reprendre=premiere)
    finally:
        campagne.envoyer = vrai_envoyer

    nb_a4 = 2 * 4   # 4 variantes de A4, 2 répétitions : toutes manquantes
    assert len(envoyes) == 1 + nb_a4           # la ligne en erreur + A4
    finales = lire_csv(reprise)
    assert len(finales) == len(lignes) + nb_a4  # une seule ligne par tentative
    assert not any(l["erreur"] for l in finales)
    assert lire_csv(premiere)[0]["erreur"]      # le fichier d'origine est intact


def test_delai_par_defaut_5_minutes():
    assert campagne.DELAI_S == 300


def test_filtre_sur_quelques_scenarios(fausse_api, tmp_path):
    lignes = lire_csv(campagne.lancer_campagne("A", 1, 1, ["A1", "A5"], avec_benin=False,
                                               dossier_sortie=tmp_path))
    assert {l["id"] for l in lignes} == {"A1", "A5"}



def test_campagne_avec_le_jeu_d_attaques_nouvelles(fausse_api, tmp_path):
    fichier = campagne.lancer_campagne(
        "B", 1, 1, dossier_sortie=tmp_path,
        fichier_scenarios="attacks/nouvelles/scenarios.yaml",
        fichier_benin="attacks/nouvelles/benign.yaml")
    ids = {l["id"] for l in lire_csv(fichier)}
    assert "N1" in ids and "L01" in ids and "A1" not in ids and "B01" not in ids
