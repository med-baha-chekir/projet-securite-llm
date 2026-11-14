"""
Tests du module partagé (app/shared).

- config, journal, outils, boucle d'outils : tests rapides, sans le modèle
  (Ollama est remplacé par une fausse réponse : on dit qu'il est « simulé ») ;
- RAG : test d'intégration avec le vrai Ollama, ignoré s'il n'est pas lancé.
"""

import dataclasses
import json

import ollama
import pytest

from app.shared import llm
from app.shared.config import charger_config
from app.shared.journal import journaliser
from app.shared.outils import SCHEMAS_OUTILS, BoiteOutils
from app.shared.rag import BaseDocumentaire, decouper_document


@pytest.fixture
def config(tmp_path):
    """Configuration normale, mais avec les journaux dans un dossier temporaire."""
    return dataclasses.replace(charger_config(), dossier_logs=tmp_path / "logs")


def lire_jsonl(fichier):
    return [json.loads(l) for l in fichier.read_text(encoding="utf-8").splitlines()]


# ---------- config ----------

def test_config_lue_depuis_le_fichier_env(tmp_path, monkeypatch):
    monkeypatch.delenv("MODEL_NAME", raising=False)
    monkeypatch.delenv("LLM_SEED", raising=False)
    env = tmp_path / ".env"
    env.write_text("# commentaire\nMODEL_NAME=modele-test\nLLM_SEED=7\n", encoding="utf-8")
    config = charger_config(env)
    assert config.modele == "modele-test"
    assert config.graine == 7


def test_variable_d_environnement_prioritaire_sur_le_fichier(tmp_path, monkeypatch):
    # Dans Docker, la valeur fournie par docker-compose doit gagner
    monkeypatch.setenv("MODEL_NAME", "modele-docker")
    env = tmp_path / ".env"
    env.write_text("MODEL_NAME=modele-fichier\n", encoding="utf-8")
    assert charger_config(env).modele == "modele-docker"


# ---------- journal ----------

def test_journal_ecrit_une_ligne_json_par_evenement(tmp_path):
    journaliser(tmp_path, "A", {"question": "Bonjour"})
    journaliser(tmp_path, "A", {"question": "Prix du kWh ?"})
    lignes = lire_jsonl(tmp_path / "A.jsonl")
    assert [l["question"] for l in lignes] == ["Bonjour", "Prix du kWh ?"]
    assert all(l["version"] == "A" and "horodatage" in l for l in lignes)


# ---------- outils ----------

def test_fiche_client_trouvee_et_introuvable(config):
    outils = BoiteOutils(config)
    assert outils.consulter_fiche_client("C003")["nom"] == "Léa Fontanier"
    assert outils.consulter_fiche_client("c003")["id"] == "C003"  # minuscules acceptées
    assert "erreur" in outils.consulter_fiche_client("C999")


def test_remboursement_et_email_sont_simules_et_journalises(config):
    outils = BoiteOutils(config)
    outils.creer_remboursement("C001", 50)
    outils.envoyer_email("pirate@exemple.test", "données")
    actions = lire_jsonl(config.dossier_logs / "actions_simulees.jsonl")
    assert [a["action"] for a in actions] == ["remboursement", "email"]
    assert actions[0]["montant"] == 50.0


def test_chaque_outil_decrit_au_modele_existe_en_python(config):
    noms_decrits = {s["function"]["name"] for s in SCHEMAS_OUTILS}
    assert noms_decrits == set(BoiteOutils(config).fonctions())


# ---------- appel au modèle et boucle d'outils (Ollama simulé) ----------

def fausse_reponse(texte="", appels=None):
    """Construit une réponse au format Ollama, sans appeler le modèle."""
    tool_calls = [
        ollama.Message.ToolCall(function=ollama.Message.ToolCall.Function(name=n, arguments=a))
        for n, a in (appels or [])
    ]
    return ollama.ChatResponse(
        model="faux", message=ollama.Message(role="assistant", content=texte,
                                             tool_calls=tool_calls or None))


def test_temperature_et_graine_viennent_de_la_config(config, monkeypatch):
    recu = {}

    class FauxClient:
        def __init__(self, host):
            recu["host"] = host

        def chat(self, **kwargs):
            recu.update(kwargs)
            return fausse_reponse("ok")

    monkeypatch.setattr(llm.ollama, "Client", FauxClient)
    llm.appeler_modele(config, [{"role": "user", "content": "Bonjour"}])
    assert recu["options"] == {"temperature": config.temperature, "seed": config.graine}
    assert recu["model"] == config.modele

    llm.appeler_modele(config, [], graine=43)  # graine d'une répétition précise
    assert recu["options"]["seed"] == 43


def test_boucle_execute_l_outil_puis_renvoie_la_reponse_finale(config, monkeypatch):
    # 1er appel : le modèle demande un outil ; 2e appel : il répond
    reponses = iter([
        fausse_reponse(appels=[("consulter_fiche_client", {"id_client": "C001"})]),
        fausse_reponse("Votre solde est de -42,80 €."),
    ])
    messages_vus = []

    def faux_appel(config, messages, outils, graine):
        messages_vus.append(list(messages))
        return next(reponses)

    monkeypatch.setattr(llm, "appeler_modele", faux_appel)
    outils = BoiteOutils(config)
    resultat = llm.discuter_avec_outils(config, [{"role": "user", "content": "Mon solde ?"}],
                                        SCHEMAS_OUTILS, outils.fonctions())

    assert resultat.texte == "Votre solde est de -42,80 €."
    assert resultat.appels_outils[0]["nom"] == "consulter_fiche_client"
    assert resultat.appels_outils[0]["resultat"]["id"] == "C001"
    # Au 2e appel, le résultat de l'outil a bien été renvoyé au modèle
    dernier = messages_vus[1][-1]
    assert dernier["role"] == "tool" and "Camille Ravenel" in dernier["content"]


def test_outil_inconnu_ou_mauvais_parametres_ne_plantent_pas(config, monkeypatch):
    reponses = iter([
        fausse_reponse(appels=[("supprimer_base", {}),
                               ("consulter_fiche_client", {"mauvais": "x"})]),
        fausse_reponse("fin"),
    ])
    monkeypatch.setattr(llm, "appeler_modele", lambda *a, **k: next(reponses))
    resultat = llm.discuter_avec_outils(config, [], SCHEMAS_OUTILS, BoiteOutils(config).fonctions())
    assert "outil inconnu" in resultat.appels_outils[0]["resultat"]["erreur"]
    assert "paramètres invalides" in resultat.appels_outils[1]["resultat"]["erreur"]


def test_boucle_limitee_en_nombre_de_tours(config, monkeypatch):
    # Un modèle qui redemande un outil à l'infini doit être arrêté
    monkeypatch.setattr(llm, "appeler_modele", lambda *a, **k: fausse_reponse(
        appels=[("consulter_fiche_client", {"id_client": "C001"})]))
    resultat = llm.discuter_avec_outils(config, [], SCHEMAS_OUTILS,
                                        BoiteOutils(config).fonctions(), max_tours=3)
    assert len(resultat.appels_outils) == 3
    assert "pas pu terminer" in resultat.texte


# ---------- RAG ----------

def test_decoupage_par_section():
    texte = "# Titre\n\n> avertissement\n\n## Partie 1\nA\n\n## Partie 2\nB"
    morceaux = decouper_document(texte)
    assert len(morceaux) == 2
    assert morceaux[0].startswith("# Titre") and "Partie 1" in morceaux[0]
    assert "Partie 2" in morceaux[1] and "Partie 1" not in morceaux[1]


def test_document_sans_section_reste_entier_avec_son_piege(config):
    texte = (config.dossier_documents / "guide_economies_energie.md").read_text(encoding="utf-8")
    morceaux = decouper_document(texte)
    assert len(morceaux) == 1 and "PWNED-A5" in morceaux[0]


def ollama_disponible(config) -> bool:
    try:
        ollama.Client(host=config.ollama_url).list()
        return True
    except Exception:
        return False


@pytest.mark.parametrize("question, document_attendu", [
    ("Quel est le prix du kWh ?", "tarifs.md"),
    ("Comment économiser de l'énergie chez moi ?", "guide_economies_energie.md"),
    ("Comment être remboursé ?", "politique_remboursement.md"),
])
def test_rag_retrouve_le_bon_document(config, question, document_attendu):
    if not ollama_disponible(config):
        pytest.skip("Ollama n'est pas lancé (docker compose up -d)")
    base = BaseDocumentaire(config)
    base.indexer()
    assert base.rechercher(question, k=1)[0]["source"] == document_attendu
