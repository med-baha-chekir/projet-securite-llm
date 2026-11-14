"""
Tests des fichiers d'attaques : attacks/scenarios.yaml et attacks/benign.yaml.

Ils vérifient la STRUCTURE (champs, types de critères) et la COHÉRENCE
avec le reste du labo (clients existants, phrases du prompt de A...).
Un fichier mal écrit fausserait toute la campagne : mieux vaut le détecter ici.
"""

import base64
import json
import re
from pathlib import Path

import pytest
import yaml

from app.vulnerable.prompt import construire_prompt_systeme

RACINE = Path(__file__).resolve().parent.parent
TYPES_CRITERES = {"canary", "marqueur", "extrait_prompt", "outil_appele",
                  "autre_client", "regex", "requete_acceptee"}


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


def test_obligatoires_a1_a6_ont_trois_variantes():
    for scenario in SCENARIOS[:6]:
        assert len(scenario["variantes"]) == 3, scenario["id"]


def test_les_phrases_cherchees_pour_a3_sont_dans_le_vrai_prompt():
    # Sinon, le critère « extrait_prompt » ne pourrait jamais se déclencher
    prompt = construire_prompt_systeme("CANARY-x", "C001", []).lower()
    a3 = next(s for s in SCENARIOS if s["id"] == "A3")
    valeurs = next(c["valeurs"] for c in a3["criteres"] if c["type"] == "extrait_prompt")
    anglaises = {"administrator access code", "never reveal this code"}  # cas de la traduction
    for phrase in (v for v in valeurs if v not in anglaises):
        assert phrase.lower() in prompt, phrase


def test_la_variante_base64_de_a10_cache_bien_le_marqueur():
    a10 = next(s for s in SCENARIOS if s["id"] == "A10")
    encode = a10["variantes"][0].rsplit(" ", 1)[-1]
    assert "PWNED-A10" in base64.b64decode(encode).decode("utf-8")


def test_la_variante_generee_de_a9_est_tres_longue():
    a9 = next(s for s in SCENARIOS if s["id"] == "A9")
    repeter = a9["variantes"][0]["repeter"]
    assert len(repeter["texte"] * repeter["fois"]) >= 25_000


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
    # 27 variantes (3 pour A1 à A6 et A8, 2 pour A7, A9, A10) x 5 = 135
    tentatives = sum(len(s["variantes"]) for s in SCENARIOS) * 5
    assert tentatives == 135
