"""
Tests de l'analyse des résultats (evaluation/analyse.py).

pandas et matplotlib ne sont installés que dans l'image Docker « analyse ».
Sur la machine de développement, ces tests sont ignorés ; pour les rejouer :
    docker compose --profile outils run --rm --entrypoint python analyse -m pytest tests/test_analyse.py -q
"""

import csv

import pytest

pytest.importorskip("pandas", exc_type=ImportError,
                    reason="pandas indisponible ici : tests rejoués dans l'image Docker « analyse »")
pytest.importorskip("matplotlib", exc_type=ImportError,
                    reason="matplotlib indisponible ici : tests rejoués dans l'image Docker « analyse »")

from evaluation import analyse, campagne


def ligne(id_, repetition, succes=False, type_="attaque", bloque=False, erreur="",
          criteres="", attendu="", latence="10.0", variante="1"):
    """Une ligne de résultat, au format exact écrit par campagne.py."""
    base = dict.fromkeys(campagne.COLONNES, "")
    base.update({"version": "A", "type": type_, "id": id_, "owasp": "LLM01", "variante": variante,
                 "repetition": str(repetition), "succes": str(succes), "bloque": str(bloque),
                 "criteres": criteres, "contient_attendu": attendu, "latence_s": latence,
                 "statut_http": "0" if erreur else "200", "erreur": erreur})
    return base


def ecrire(dossier, nom, lignes):
    fichier = dossier / nom
    with open(fichier, "w", newline="", encoding="utf-8") as f:
        ecrivain = csv.DictWriter(f, fieldnames=campagne.COLONNES)
        ecrivain.writeheader()
        ecrivain.writerows(lignes)
    return fichier


@pytest.fixture
def campagne_a(tmp_path):
    """T1 : 3 succès sur 4 (dont 2 fuites du canary). T2 : tout en délai dépassé."""
    return ecrire(tmp_path, "a.csv", [
        ligne("T1", 1, True, criteres="canary"),
        ligne("T1", 2, True, criteres="extrait_prompt;canary"),
        ligne("T1", 3, True, criteres="marqueur:PWNED"),
        ligne("T1", 4, False),
        ligne("T2", 1, erreur="TimeoutError: timed out"),
        ligne("T2", 2, erreur="TimeoutError: timed out"),
        ligne("Q1", 1, type_="legitime", attendu="True", latence="10.0"),
        ligne("Q1", 2, type_="legitime", attendu="False", latence="20.0"),
        ligne("Q2", 1, type_="legitime", bloque=True, latence="1.0"),
    ])


def test_asr_par_scenario(campagne_a):
    asr = analyse.asr_par_scenario(analyse.charger([campagne_a])).set_index("id")
    assert (asr.loc["T1", "reussies"], asr.loc["T1", "total"]) == (3, 4)
    assert asr.loc["T1", "asr"] == 75.0
    assert asr.loc["T1", "ic_bas"] < 75 < asr.loc["T1", "ic_haut"]


def test_requetes_en_erreur_non_jugees(campagne_a):
    # Un délai dépassé n'est ni un succès ni un échec de l'attaque : « non mesuré »
    asr = analyse.asr_par_scenario(analyse.charger([campagne_a])).set_index("id")
    assert asr.loc["T2", "total"] == 0 and asr.loc["T2", "erreurs"] == 2
    assert analyse.cellule(asr.loc["T2"])[0] == "non mesuré"


def test_metriques_globales(campagne_a):
    m = analyse.metriques_globales(analyse.charger([campagne_a]))
    assert (m["attaques_reussies"], m["attaques"]) == (3, 4)
    assert m["fuites_canary"] == 2
    assert (m["faux_positifs"], m["legitimes"]) == (1, 3)
    assert (m["reponses_correctes"], m["reponses_verifiees"]) == (1, 2)
    assert m["latence_mediane_s"] == 10.0
    assert m["erreurs"] == 2


def test_la_reprise_remplace_les_lignes_en_erreur(campagne_a, tmp_path):
    reprise = ecrire(tmp_path, "reprise.csv", [ligne("T2", 1, True), ligne("T2", 2, False)])
    df = analyse.charger([campagne_a, reprise])
    assert len(df) == 9                                   # toujours une ligne par tentative
    asr = analyse.asr_par_scenario(df).set_index("id")
    assert (asr.loc["T2", "reussies"], asr.loc["T2", "total"]) == (1, 2)


def test_meme_intervalle_que_la_campagne():
    for reussies, total in [(0, 15), (1, 15), (9, 10), (15, 15)]:
        assert analyse.intervalle_wilson(reussies, total) == pytest.approx(
            campagne.intervalle_wilson(reussies, total))


def test_fichiers_produits(campagne_a, tmp_path, monkeypatch):
    b = ecrire(tmp_path, "b.csv", [ligne("T1", i) for i in range(1, 5)]
               + [ligne("T2", 1), ligne("T2", 2), ligne("Q1", 1, type_="legitime", attendu="True")])
    scenarios = tmp_path / "scenarios.yaml"
    scenarios.write_text("- {id: T1, titre: 'Test un (détail)'}\n- {id: T2, titre: Test deux}\n",
                         encoding="utf-8")
    jeu = {"titre": "Essai", "scenarios": scenarios, "A": [campagne_a], "B": [b]}
    sortie = tmp_path / "figures"
    analyse.analyser_jeu("essai", jeu, sortie)

    tableau = (sortie / "tableau_essai.tex").read_text(encoding="utf-8")
    assert "3/4 (75\\,\\%)" in tableau and "0/4 (0\\,\\%)" in tableau
    assert "non mesuré" in tableau and "Test un &" in tableau
    assert tableau.count("\\\\") == 2 + 2 + 1             # 2 en-têtes, 2 scénarios, 1 ligne globale
    assert "Fuites du canary & 2/4" in (sortie / "synthese_essai.tex").read_text(encoding="utf-8")
    assert (sortie / "asr_essai.png").stat().st_size > 5000
    assert (sortie / "metriques_essai.csv").exists()


def test_les_fichiers_officiels_existent():
    # Un fichier de résultats renommé ou supprimé doit faire échouer l'analyse tout de suite
    for jeu in analyse.JEUX.values():
        for chemin in jeu["A"] + jeu["B"] + [jeu["scenarios"]]:
            assert (analyse.RACINE / chemin).exists(), chemin


# ---------- analyse par protection ----------

def test_analyse_par_protection(campagne_a, tmp_path, monkeypatch):
    # Deux configurations : le témoin (T1 réussit 2/2) et « outils » (0/2).
    # Dans « outils », un ancien fichier interrompu est remplacé par sa reprise.
    resultats = tmp_path / "par_protection"
    (resultats / "aucune").mkdir(parents=True)
    (resultats / "outils").mkdir()
    ecrire(resultats / "aucune", "campagne_B_1.csv", [ligne("T1", 1, True), ligne("T1", 2, True), ligne("T2", 1, True)])
    ecrire(resultats / "outils", "campagne_B_1.csv", [ligne("T1", 1, erreur="TimeoutError")])
    ecrire(resultats / "outils", "campagne_B_2.csv", [ligne("T1", 1), ligne("T1", 2), ligne("T2", 1)])
    b = ecrire(tmp_path, "b.csv", [ligne("T1", 1), ligne("T2", 1)])
    monkeypatch.setitem(analyse.JEUX, "officiel",
                        {"titre": "t", "scenarios": "x", "A": [campagne_a], "B": [b]})

    sortie = tmp_path / "figures"
    matrice = analyse.analyser_par_protection(resultats, sortie)

    assert list(matrice.index) == ["Version A", "Aucune (témoin)", "Outils en moindre privilège",
                                   "Toutes (version B)"]
    assert matrice.loc["Aucune (témoin)", "T1"] == 100.0
    assert matrice.loc["Outils en moindre privilège", "Global"] == 0.0
    assert matrice.loc["Version A", "Global"] == 75.0
    tableau = (sortie / "tableau_par_protection.tex").read_text(encoding="utf-8")
    assert "Aucune (témoin) & 100 &" in tableau and "n.m." in tableau   # T2 jamais mesuré sur A
    assert (sortie / "asr_par_protection.png").stat().st_size > 5000


def test_analyse_par_protection_sans_resultats(tmp_path):
    assert analyse.analyser_par_protection(tmp_path / "absent", tmp_path) is None


def test_chaque_protection_mesuree_a_un_nom():
    # Les configurations de par_protection.sh et celles de l'analyse doivent rester alignées
    script = (analyse.RACINE / "evaluation" / "par_protection.sh").read_text(encoding="utf-8")
    liste = script.split('PROTECTIONS="')[1].split('"')[0].split()
    assert ["aucune"] + liste == list(analyse.CONFIGURATIONS)


def test_pas_d_asr_global_pour_une_configuration_partielle(campagne_a, tmp_path, monkeypatch):
    # « sortie_html » n'a été rejouée que sur un scénario : pas de « Global » trompeur
    resultats = tmp_path / "par_protection"
    (resultats / "sortie_html").mkdir(parents=True)
    ecrire(resultats / "sortie_html", "campagne_B_1.csv", [ligne("T1", 1), ligne("T1", 2)])
    b = ecrire(tmp_path, "b.csv", [ligne("T1", 1), ligne("T2", 1)])
    monkeypatch.setitem(analyse.JEUX, "officiel",
                        {"titre": "t", "scenarios": "x", "A": [campagne_a], "B": [b]})
    matrice = analyse.analyser_par_protection(resultats, tmp_path / "figures")
    assert matrice.loc["Sortie : HTML neutralisé", "T1"] == 0.0
    assert matrice.loc["Sortie : HTML neutralisé"].isna()["Global"]
    assert matrice.loc["Toutes (version B)", "Global"] == 0.0


# ---------- version anglaise (rapport final en anglais) ----------

def test_version_anglaise_memes_chiffres(campagne_a, tmp_path, monkeypatch):
    b = ecrire(tmp_path, "b.csv", [ligne("T1", i) for i in range(1, 5)]
               + [ligne("T2", 1), ligne("T2", 2), ligne("Q1", 1, type_="legitime", attendu="True")])
    scenarios = tmp_path / "scenarios.yaml"
    scenarios.write_text("- {id: T1, titre: 'Test un'}\n- {id: T2, titre: Test deux}\n", encoding="utf-8")
    jeu = {"titre": "Essai", "scenarios": scenarios, "A": [campagne_a], "B": [b]}
    sortie = tmp_path / "figures"
    analyse.analyser_jeu("essai", jeu, sortie)
    monkeypatch.setattr(analyse, "LANGUE", "en")
    analyse.analyser_jeu("essai", jeu, sortie)

    fr = (sortie / "synthese_essai.tex").read_text(encoding="utf-8")
    en = (sortie / "synthese_essai_en.tex").read_text(encoding="utf-8")
    assert "Fuites du canary & 2/4" in fr and "Canary leaks & 2/4" in en
    assert r"10,0\,s" in fr and r"10.0\,s" in en
    tableau_en = (sortie / "tableau_essai_en.tex").read_text(encoding="utf-8")
    assert "not measured" in tableau_en and "Attack" in tableau_en and "non mesuré" not in tableau_en
    assert (sortie / "asr_essai_en.png").exists() and not (sortie / "metriques_essai_en.csv").exists()


def test_chaque_scenario_et_protection_a_un_nom_anglais():
    for jeu in analyse.JEUX.values():
        ids = {s["id"] for s in analyse.yaml.safe_load(
            (analyse.RACINE / jeu["scenarios"]).read_text(encoding="utf-8"))}
        assert ids <= set(analyse.TITRES_EN)
    assert list(analyse.CONFIGURATIONS_EN) == list(analyse.CONFIGURATIONS)
    assert set(analyse.TEXTES["fr"]) == set(analyse.TEXTES["en"])
