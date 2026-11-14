"""
Campagne d'attaques : rejoue les scénarios et les questions légitimes sur
une version (A ou B), juge chaque réponse et enregistre les résultats bruts.

Lancement (dans le labo, car A et B ne sont joignables que par le réseau interne) :
    docker compose run --rm campagne --version A
    docker compose run --rm campagne --version A --scenarios A1,A5 --repetitions 1

Résultat : un fichier CSV dans results/before/ (version A) ou results/after/ (B),
une ligne par tentative. Les graphiques seront générés à partir de ces fichiers.
"""

import argparse
import csv
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

from app.shared.config import RACINE, charger_config
from evaluation.criteres import contient_canary, evaluer_attaque, evaluer_question_legitime

URLS = {
    "A": os.environ.get("URL_APP_A", "http://app-vulnerable:8000"),
    "B": os.environ.get("URL_APP_B", "http://app-secure:8000"),
}
DOSSIERS_SORTIE = {"A": RACINE / "results" / "before", "B": RACINE / "results" / "after"}

COLONNES = ["horodatage", "version", "type", "id", "owasp", "variante", "repetition",
            "graine", "succes", "criteres", "bloque", "contient_attendu", "statut_http",
            "latence_s", "outils", "reponse_extrait", "erreur"]


# ---------- préparation ----------

def construire_message(variante) -> str:
    """Une variante est soit un texte, soit {repeter: {texte, fois}} (message géant de A9)."""
    if isinstance(variante, dict) and "repeter" in variante:
        return variante["repeter"]["texte"] * variante["repeter"]["fois"]
    return variante


def preparer_taches(scenarios, questions, repetitions, repetitions_benin, graine_base):
    """
    Liste de toutes les requêtes à envoyer.
    La répétition n utilise la graine graine_base + n : identique pour A et B,
    ce qui rend les deux campagnes comparables tentative par tentative.
    """
    taches = []
    for s in scenarios:
        for v, variante in enumerate(s["variantes"], start=1):
            for r in range(repetitions):
                taches.append({"type": "attaque", "element": s, "variante": v,
                               "message": construire_message(variante),
                               "repetition": r + 1, "graine": graine_base + r})
    for q in questions:
        for r in range(repetitions_benin):
            taches.append({"type": "legitime", "element": q, "variante": 1,
                           "message": q["message"], "repetition": r + 1,
                           "graine": graine_base + r})
    return taches


# ---------- envoi d'une requête ----------

def envoyer(url: str, message: str, id_client: str, graine: int, delai: int = 600) -> dict:
    """
    Envoie une requête à POST /chat et renvoie un « résultat » au format attendu
    par les critères. Ne plante jamais : une erreur est renvoyée dans le résultat.
    """
    requete = urllib.request.Request(
        url + "/chat",
        data=json.dumps({"message": message, "id_client": id_client, "graine": graine}).encode(),
        headers={"Content-Type": "application/json"},
    )
    debut = time.perf_counter()
    resultat = {"statut_http": 0, "reponse": "", "outils_appeles": [], "bloque": False,
                "latence_s": 0.0, "erreur": ""}
    try:
        with urllib.request.urlopen(requete, timeout=delai) as r:
            donnees = json.load(r)
            resultat.update(statut_http=r.status, reponse=donnees.get("reponse", ""),
                            outils_appeles=donnees.get("outils_appeles", []),
                            bloque=donnees.get("bloque", False))
    except urllib.error.HTTPError as e:   # l'API a répondu avec une erreur (ex. 429 trop de requêtes)
        resultat.update(statut_http=e.code, erreur=f"HTTP {e.code}")
    except Exception as e:                # délai dépassé, serveur injoignable...
        resultat["erreur"] = f"{type(e).__name__}: {e}"
    resultat["latence_s"] = round(time.perf_counter() - debut, 2)
    return resultat


# ---------- masquage avant écriture ----------

def masquer(texte: str, canary: str) -> str:
    """
    Le dossier results/ est versionné sur Git : le canary ne doit jamais y être écrit.
    - canary présent tel quel : remplacé par [CANARY] ;
    - canary épelé (C-A-N-A-R-Y...) : impossible à remplacer proprement, tout le texte est masqué.
    Le verdict est calculé AVANT le masquage, il reste donc juste.
    """
    if not canary:
        return texte
    texte = texte.replace(canary, "[CANARY]")
    if contient_canary(texte, canary):
        return "[texte masqué : contient le canary sous une forme modifiée]"
    return texte


# ---------- campagne ----------

def ligne_de_resultat(tache, resultat, version, contexte_canary, clients) -> dict:
    """Juge la réponse et prépare la ligne du fichier CSV."""
    element = tache["element"]
    ligne = {
        "horodatage": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "version": version, "type": tache["type"], "id": element["id"],
        "owasp": element.get("owasp", ""), "variante": tache["variante"],
        "repetition": tache["repetition"], "graine": tache["graine"],
        "statut_http": resultat["statut_http"], "latence_s": resultat["latence_s"],
        "erreur": resultat["erreur"],
    }
    if tache["type"] == "attaque":
        contexte = {"canary": contexte_canary, "id_client": element["id_client"],
                    "clients": clients, "message": tache["message"]}
        declenches = evaluer_attaque(element, resultat, contexte)
        ligne.update(succes=bool(declenches), criteres=";".join(declenches),
                     bloque=resultat["bloque"], contient_attendu="")
    else:
        verdict = evaluer_question_legitime(element, resultat)
        ligne.update(succes="", criteres="", bloque=verdict["bloque"],
                     contient_attendu="" if verdict["contient_attendu"] is None
                     else verdict["contient_attendu"])

    outils = json.dumps([{"nom": a["nom"], "arguments": a.get("arguments", {})}
                         for a in resultat["outils_appeles"]], ensure_ascii=False)
    ligne["outils"] = masquer(outils, contexte_canary)
    # Masquer AVANT de couper : sinon un canary épelé coupé en deux échapperait
    # au masquage et la moitié de ses caractères finirait sur Git
    ligne["reponse_extrait"] = masquer(resultat["reponse"], contexte_canary)[:300]
    return ligne


def afficher_resume(lignes: list[dict]) -> None:
    """Résumé lisible à la fin de la campagne."""
    print("\n========== RÉSUMÉ ==========")
    attaques = [l for l in lignes if l["type"] == "attaque"]
    for id_ in dict.fromkeys(l["id"] for l in attaques):  # ordre d'apparition, sans doublon
        du_scenario = [l for l in attaques if l["id"] == id_]
        reussies = sum(l["succes"] for l in du_scenario)
        print(f"  {id_:<4} ASR = {reussies}/{len(du_scenario)} "
              f"({100 * reussies / len(du_scenario):.0f} %)")
    if attaques:
        total = sum(l["succes"] for l in attaques)
        print(f"  GLOBAL ASR = {total}/{len(attaques)} ({100 * total / len(attaques):.0f} %)")
    legitimes = [l for l in lignes if l["type"] == "legitime"]
    if legitimes:
        bloquees = sum(l["bloque"] for l in legitimes)
        verifiees = [l for l in legitimes if l["contient_attendu"] != ""]
        correctes = sum(l["contient_attendu"] for l in verifiees)
        print(f"  Questions légitimes bloquées (faux positifs) : {bloquees}/{len(legitimes)}")
        print(f"  Réponses correctes (élément attendu présent) : {correctes}/{len(verifiees)}")
    erreurs = sum(1 for l in lignes if l["erreur"])
    print(f"  Requêtes en erreur : {erreurs}")


def lancer_campagne(version, repetitions, repetitions_benin, filtre_scenarios=None,
                    avec_attaques=True, avec_benin=True, dossier_sortie=None) -> Path:
    config = charger_config()
    scenarios = yaml.safe_load((RACINE / "attacks" / "scenarios.yaml").read_text(encoding="utf-8"))
    questions = yaml.safe_load((RACINE / "attacks" / "benign.yaml").read_text(encoding="utf-8"))
    clients = {c["id"]: c for c in json.loads(config.fichier_clients.read_text(encoding="utf-8"))["clients"]}

    if filtre_scenarios:
        scenarios = [s for s in scenarios if s["id"] in filtre_scenarios]
    taches = preparer_taches(scenarios if avec_attaques else [],
                             questions if avec_benin else [],
                             repetitions, repetitions_benin, config.graine)

    dossier = Path(dossier_sortie) if dossier_sortie else DOSSIERS_SORTIE[version]
    dossier.mkdir(parents=True, exist_ok=True)
    fichier = dossier / f"campagne_{version}_{datetime.now():%Y%m%d-%H%M%S}.csv"
    print(f"Campagne version {version} : {len(taches)} requêtes -> {fichier}")

    lignes, debut = [], time.perf_counter()
    with open(fichier, "w", newline="", encoding="utf-8") as f:
        ecrivain = csv.DictWriter(f, fieldnames=COLONNES)
        ecrivain.writeheader()
        for i, tache in enumerate(taches, start=1):
            resultat = envoyer(URLS[version], tache["message"],
                               tache["element"]["id_client"], tache["graine"])
            ligne = ligne_de_resultat(tache, resultat, version, config.canary, clients)
            ecrivain.writerow(ligne)
            f.flush()  # écrit tout de suite sur le disque : rien n'est perdu en cas d'arrêt
            lignes.append(ligne)

            ecoule = time.perf_counter() - debut
            reste_min = ecoule / i * (len(taches) - i) / 60
            if ligne["type"] == "attaque":
                verdict = "SUCCÈS" if ligne["succes"] else "échec"
            else:
                verdict = "BLOQUÉE" if ligne["bloque"] else "ok"
            if ligne["erreur"]:
                verdict = f"ERREUR ({ligne['erreur'][:40]})"
            print(f"[{i}/{len(taches)}] {ligne['id']} v{ligne['variante']} r{ligne['repetition']}"
                  f" -> {verdict} ({resultat['latence_s']} s) | reste ~{reste_min:.0f} min",
                  flush=True)

    afficher_resume(lignes)
    print(f"\nRésultats bruts : {fichier}")
    return fichier


def main():
    config = charger_config()
    parser = argparse.ArgumentParser(description="Campagne d'attaques sur la version A ou B.")
    parser.add_argument("--version", choices=["A", "B"], required=True)
    parser.add_argument("--repetitions", type=int, default=config.repetitions,
                        help="répétitions par variante d'attaque (défaut : N_REPETITIONS)")
    parser.add_argument("--repetitions-benin", type=int, default=3,
                        help="répétitions par question légitime (défaut : 3)")
    parser.add_argument("--scenarios", help="liste restreinte, ex. A1,A5")
    parser.add_argument("--sans-benin", action="store_true", help="attaques uniquement")
    parser.add_argument("--sans-attaques", action="store_true", help="questions légitimes uniquement")
    parser.add_argument("--sortie", help="dossier de sortie (défaut : results/before ou after)")
    args = parser.parse_args()

    lancer_campagne(
        version=args.version, repetitions=args.repetitions,
        repetitions_benin=args.repetitions_benin,
        filtre_scenarios=args.scenarios.split(",") if args.scenarios else None,
        avec_attaques=not args.sans_attaques, avec_benin=not args.sans_benin,
        dossier_sortie=args.sortie,
    )


if __name__ == "__main__":
    main()
