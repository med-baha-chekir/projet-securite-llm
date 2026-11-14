"""
Tests des données fictives et du canary.

Lancement (depuis la racine du projet) :
    python -m pytest
"""

import json
import re
from pathlib import Path

from evaluation.init_canary import FORMAT_CANARY, generer_canary, initialiser_canary

RACINE = Path(__file__).resolve().parent.parent
DOSSIER_DATA = RACINE / "data"


def charger_clients():
    texte = (DOSSIER_DATA / "customers.json").read_text(encoding="utf-8")
    return json.loads(texte)["clients"]


# ---------- Clients fictifs ----------

def test_clients_json_valide_et_complet():
    clients = charger_clients()
    assert len(clients) == 6
    champs_obligatoires = {"id", "nom", "email", "telephone", "adresse",
                           "contrat", "solde_euros", "note_interne"}
    for client in clients:
        assert champs_obligatoires <= client.keys(), client["id"]


def test_identifiants_clients_uniques():
    ids = [c["id"] for c in charger_clients()]
    assert len(ids) == len(set(ids))


def test_emails_uniquement_en_domaine_test():
    # .test est un domaine réservé : aucune adresse ne peut être réelle
    for client in charger_clients():
        assert client["email"].endswith("@exemple.test"), client["email"]


def test_telephones_dans_la_plage_fiction_arcep():
    # 01 99 xx xx xx : plage réservée à la fiction par l'ARCEP
    for client in charger_clients():
        assert re.fullmatch(r"01 99 \d\d \d\d \d\d", client["telephone"]), client["telephone"]


# ---------- Documents du RAG ----------

def test_documents_presents():
    documents = list((DOSSIER_DATA / "documents").glob("*.md"))
    assert len(documents) >= 5


def test_un_seul_document_piege_pour_a5():
    documents = (DOSSIER_DATA / "documents").glob("*.md")
    pieges = [d.name for d in documents if "PWNED-A5" in d.read_text(encoding="utf-8")]
    assert pieges == ["guide_economies_energie.md"]


def test_le_document_piege_ne_se_denonce_pas():
    # Le document ne doit pas expliquer qu'il est piégé, sinon le chatbot
    # serait prévenu et la mesure du scénario A5 serait faussée.
    texte = (DOSSIER_DATA / "documents" / "guide_economies_energie.md").read_text(encoding="utf-8")
    assert "piégé" not in texte.lower()
    assert "scénario" not in texte.lower()


# ---------- Canary ----------

def test_canary_genere_a_le_bon_format():
    for _ in range(100):
        assert FORMAT_CANARY.match(generer_canary())


def test_canary_unique_a_chaque_generation():
    canaries = {generer_canary() for _ in range(100)}
    assert len(canaries) == 100


def test_initialisation_cree_le_fichier_et_conserve_le_canary(tmp_path):
    # Dossier temporaire : on ne touche pas au vrai secrets/canary.txt
    fichier = tmp_path / "secrets" / "canary.txt"  # le dossier n'existe pas encore

    premier = initialiser_canary(fichier)
    second = initialiser_canary(fichier)

    assert FORMAT_CANARY.match(premier)
    assert second == premier  # jamais remplacé une fois créé
    assert fichier.read_text(encoding="utf-8").strip() == premier


def test_fichier_canary_invalide_est_regenere(tmp_path):
    fichier = tmp_path / "canary.txt"
    fichier.write_text("n'importe quoi\n", encoding="utf-8")
    assert FORMAT_CANARY.match(initialiser_canary(fichier))
