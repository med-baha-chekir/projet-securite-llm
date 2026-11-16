"""
Analyse des campagnes (P6) : tableaux comparatifs A / B et graphiques.

Tout est calculé à partir des fichiers bruts de results/ : aucun chiffre n'est
saisi à la main. Relancer ce script régénère les tableaux et les graphiques.

Lancement (dans Docker, comme le reste du labo) :
    docker compose --profile outils run --rm analyse

Fichiers produits dans results/figures/ :
    tableau_<jeu>.tex      ASR par scénario, A et B (prêt pour \\input{} en LaTeX)
    synthese_<jeu>.tex     métriques globales (ASR, canary, faux positifs, latence)
    asr_<jeu>.png          graphique en barres, A en rouge et B en vert
    metriques_<jeu>.csv    les mêmes chiffres, relisibles par un tableur
"""

import math
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")                      # pas d'écran dans le conteneur
import matplotlib.pyplot as plt
import pandas as pd
import yaml

RACINE = Path(__file__).resolve().parent.parent
DOSSIER_FIGURES = RACINE / "results" / "figures"

# Les campagnes analysées. Quand un jeu a plusieurs fichiers pour une version
# (campagne + reprise), ils sont fusionnés : la ligne la plus récente gagne.
JEUX = {
    "officiel": {
        "titre": "Attaques officielles A1 à A10",
        "scenarios": "attacks/scenarios.yaml",
        "A": ["results/before/campagne_A_20261115-151138.csv"],
        "B": ["results/after/campagne_B_20261115-215308.csv"],
    },
    "nouvelles": {
        "titre": "Attaques nouvelles N1 à N8 (jamais vues par B)",
        "scenarios": "attacks/nouvelles/scenarios.yaml",
        "A": ["results/nouvelles/campagne_A_20261115-232548.csv",
              "results/nouvelles/campagne_A_20261116-030506.csv"],   # reprise des questions légitimes
        "B": ["results/nouvelles/campagne_B_20261116-023838.csv"],
    },
}

CLE = ["type", "id", "variante", "repetition"]     # identifie une tentative
ROUGE, VERT = "#C0392B", "#2E9E6B"                 # A, B (paire vérifiée pour les daltoniens)


# ---------- chargement ----------

def vers_booleen(colonne: pd.Series) -> pd.Series:
    """Le CSV contient « True », « False » ou vide : on en fait de vrais booléens."""
    return colonne.astype(str).str.strip() == "True"


def charger(fichiers) -> pd.DataFrame:
    """Lit un ou plusieurs CSV de campagne et garde UNE ligne par tentative."""
    tables = [pd.read_csv(RACINE / f, dtype=str, keep_default_na=False) for f in fichiers]
    df = pd.concat(tables, ignore_index=True)
    # Une reprise rejoue les lignes en erreur : la version la plus récente remplace l'ancienne
    df = df.drop_duplicates(subset=CLE, keep="last").reset_index(drop=True)
    df["succes"] = vers_booleen(df["succes"])
    df["bloque"] = vers_booleen(df["bloque"])
    df["en_erreur"] = df["erreur"] != ""
    df["latence_s"] = pd.to_numeric(df["latence_s"], errors="coerce")
    return df


# ---------- calculs ----------

def intervalle_wilson(reussies: int, total: int) -> tuple[float, float]:
    """Intervalle de confiance à 95 % d'une proportion, en pourcentage (même formule que campagne.py)."""
    if total == 0:
        return 0.0, 0.0
    z = 1.96
    p = reussies / total
    centre = (p + z * z / (2 * total)) / (1 + z * z / total)
    marge = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / (1 + z * z / total)
    return max(0.0, 100 * (centre - marge)), min(100.0, 100 * (centre + marge))


def asr_par_scenario(df: pd.DataFrame) -> pd.DataFrame:
    """ASR par scénario. Les requêtes en erreur (délai dépassé) ne sont pas jugées :
    elles sont comptées à part, jamais comme « attaque échouée »."""
    lignes = []
    attaques = df[df["type"] == "attaque"]
    for id_, groupe in attaques.groupby("id", sort=False):
        valides = groupe[~groupe["en_erreur"]]
        total, reussies = len(valides), int(valides["succes"].sum())
        bas, haut = intervalle_wilson(reussies, total)
        lignes.append({
            "id": id_, "owasp": groupe["owasp"].iloc[0],
            "reussies": reussies, "total": total,
            "asr": 100 * reussies / total if total else float("nan"),
            "ic_bas": bas, "ic_haut": haut,
            "erreurs": int(groupe["en_erreur"].sum()),
        })
    # Ordre naturel des scénarios (A1, A2, ... A10), quel que soit l'ordre des fichiers
    lignes.sort(key=lambda l: (l["id"][0], int(l["id"][1:])))
    return pd.DataFrame(lignes)


def metriques_globales(df: pd.DataFrame) -> dict:
    """Les métriques de la section 7 du cahier des charges, pour une version."""
    attaques = df[(df["type"] == "attaque") & ~df["en_erreur"]]
    legitimes = df[(df["type"] == "legitime") & ~df["en_erreur"]]
    verifiees = legitimes[legitimes["contient_attendu"] != ""]
    # Un critère « canary » déclenché = le canary est sorti (réponse ou argument d'outil)
    fuites = attaques["criteres"].apply(lambda c: "canary" in c.split(";")).sum()
    return {
        "attaques": len(attaques),
        "attaques_reussies": int(attaques["succes"].sum()),
        "fuites_canary": int(fuites),
        "attaques_bloquees": int(attaques["bloque"].sum()),
        "legitimes": len(legitimes),
        "faux_positifs": int(legitimes["bloque"].sum()),
        "reponses_verifiees": len(verifiees),
        "reponses_correctes": int(vers_booleen(verifiees["contient_attendu"]).sum()),
        "latence_mediane_s": float(legitimes["latence_s"].median()),
        "latence_moyenne_s": float(legitimes["latence_s"].mean()),
        "erreurs": int(df["en_erreur"].sum()),
    }


# ---------- sorties LaTeX ----------

def titres_des_scenarios(fichier) -> dict:
    """Titre court de chaque scénario, lu dans le fichier d'attaques."""
    scenarios = yaml.safe_load((RACINE / fichier).read_text(encoding="utf-8"))
    return {s["id"]: s["titre"].split(" (")[0] for s in scenarios}


def cellule(ligne) -> tuple[str, str]:
    """Texte de l'ASR et de son intervalle : « 9/15 (60 %) », « 36-80 % ».
    « non mesuré » si toutes les requêtes du scénario ont échoué."""
    if ligne["total"] == 0:
        return "non mesuré", "--"
    return (f"{ligne['reussies']}/{ligne['total']} ({ligne['asr']:.0f}\\,\\%)",
            f"{ligne['ic_bas']:.0f}--{ligne['ic_haut']:.0f}\\,\\%")


def secondes(valeur: float) -> str:
    """Durée à la française : « 12,6 s »."""
    return f"{valeur:.1f}".replace(".", ",") + "\\,s"


def pourcentage(n: int, total: int) -> str:
    return f"{n}/{total} ({100 * n / total:.0f}\\,\\%)" if total else "--"


def tableau_latex(asr_a: pd.DataFrame, asr_b: pd.DataFrame, titres: dict) -> str:
    """Tableau ASR par scénario, A contre B (paquet booktabs, déjà chargé par le rapport)."""
    lignes = [
        "% Généré par evaluation/analyse.py : ne pas modifier à la main",
        "\\begin{tabular}{@{}llp{5.2cm}rrrr@{}}",
        "\\toprule",
        " & & & \\multicolumn{2}{c}{Version A} & \\multicolumn{2}{c}{Version B} \\\\",
        "\\cmidrule(lr){4-5}\\cmidrule(l){6-7}",
        "ID & OWASP & Attaque & ASR & IC 95\\,\\% & ASR & IC 95\\,\\% \\\\",
        "\\midrule",
    ]
    b_par_id = asr_b.set_index("id")
    for _, a in asr_a.iterrows():
        b = b_par_id.loc[a["id"]]
        asr_a_txt, ic_a = cellule(a)
        asr_b_txt, ic_b = cellule(b)
        lignes.append(f"{a['id']} & {a['owasp']} & {titres.get(a['id'], '')} & "
                      f"{asr_a_txt} & {ic_a} & {asr_b_txt} & {ic_b} \\\\")
    lignes += [
        "\\midrule",
        f"\\multicolumn{{3}}{{@{{}}l}}{{\\textbf{{Global}}}} & "
        f"\\textbf{{{pourcentage(int(asr_a['reussies'].sum()), int(asr_a['total'].sum()))}}} & & "
        f"\\textbf{{{pourcentage(int(asr_b['reussies'].sum()), int(asr_b['total'].sum()))}}} & \\\\",
        "\\bottomrule",
        "\\end{tabular}",
    ]
    return "\n".join(lignes) + "\n"


def synthese_latex(m_a: dict, m_b: dict) -> str:
    """Tableau des métriques globales, A contre B."""
    def ligne(nom, cle_n, cle_total):
        return (f"{nom} & {pourcentage(m_a[cle_n], m_a[cle_total])} & "
                f"{pourcentage(m_b[cle_n], m_b[cle_total])} \\\\")
    return "\n".join([
        "% Généré par evaluation/analyse.py : ne pas modifier à la main",
        "\\begin{tabular}{@{}lrr@{}}",
        "\\toprule",
        "Métrique & Version A & Version B \\\\",
        "\\midrule",
        ligne("Attaques réussies (ASR global)", "attaques_reussies", "attaques"),
        ligne("Fuites du canary", "fuites_canary", "attaques"),
        ligne("Attaques refusées par une protection", "attaques_bloquees", "attaques"),
        ligne("Questions légitimes bloquées (faux positifs)", "faux_positifs", "legitimes"),
        ligne("Réponses légitimes correctes", "reponses_correctes", "reponses_verifiees"),
        f"Latence médiane, question légitime & {secondes(m_a['latence_mediane_s'])} & "
        f"{secondes(m_b['latence_mediane_s'])} \\\\",
        f"Requêtes non jugées (délai dépassé) & {m_a['erreurs']} & {m_b['erreurs']} \\\\",
        "\\bottomrule",
        "\\end{tabular}",
    ]) + "\n"


# ---------- graphique ----------

def graphique_asr(asr_a: pd.DataFrame, asr_b: pd.DataFrame, titre: str, fichier: Path) -> None:
    """Barres groupées : ASR par scénario, A en rouge, B en vert, avec l'intervalle à 95 %."""
    b_par_id = asr_b.set_index("id")
    ids = list(asr_a["id"])
    largeur = 0.38
    fig, ax = plt.subplots(figsize=(10, 4.8))

    for decalage, table, couleur, nom in (
            (-largeur / 2, asr_a.set_index("id"), ROUGE, "Version A (vulnérable)"),
            (+largeur / 2, b_par_id, VERT, "Version B (sécurisée)")):
        for i, id_ in enumerate(ids):
            l = table.loc[id_]
            x = i + decalage
            if l["total"] == 0:                       # aucune requête jugée
                ax.text(x, 2, "non\nmesuré", ha="center", va="bottom", fontsize=7.5, color="#555555")
                continue
            # Hauteur minimale de 0,8 : une barre à 0 % reste visible (un liseré de couleur)
            ax.bar(x, max(l["asr"], 0.8), largeur - 0.03, color=couleur, label=nom if i == 0 else None)
            # Intervalle de confiance : trait gris fin, discret, avec deux petites butées
            ax.errorbar(x, l["asr"], yerr=[[l["asr"] - l["ic_bas"]], [l["ic_haut"] - l["asr"]]],
                        color="#8A8A8A", linewidth=0.9, capsize=2.5, capthick=0.9)
            # Valeur écrite juste au-dessus de la barre : la couleur n'est jamais le seul repère
            ax.text(x, l["asr"] + 2.5, f"{l['asr']:.0f} %", ha="center", va="bottom",
                    fontsize=8.5, color="#222222",
                    bbox={"facecolor": "white", "edgecolor": "none", "pad": 1.2})

    ax.set_xticks(range(len(ids)))
    owasp = asr_a.set_index("id")["owasp"].str.replace(" / ", "/")
    ax.set_xticklabels([f"{id_}\n{owasp[id_]}" for id_ in ids])
    ax.set_ylim(0, 112)
    ax.set_yticks(range(0, 101, 20))
    ax.set_ylabel("Taux de succès des attaques (ASR, %)")
    ax.set_title(titre, loc="left", fontsize=12, fontweight="bold")
    ax.yaxis.grid(True, color="#DDDDDD", linewidth=0.7)
    ax.set_axisbelow(True)
    for cote in ("top", "right", "left"):
        ax.spines[cote].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.16), ncol=2, frameon=False)
    fig.text(0.99, 0.01, "Trait gris : intervalle de confiance à 95 % (Wilson)",
             ha="right", fontsize=7.5, color="#555555")
    fig.tight_layout()
    fig.savefig(fichier, dpi=200)
    plt.close(fig)


# ---------- programme principal ----------

def analyser_jeu(nom: str, jeu: dict, dossier: Path) -> dict:
    """Produit tous les fichiers d'un jeu d'attaques et renvoie ses métriques."""
    df_a, df_b = charger(jeu["A"]), charger(jeu["B"])
    asr_a, asr_b = asr_par_scenario(df_a), asr_par_scenario(df_b)
    m_a, m_b = metriques_globales(df_a), metriques_globales(df_b)

    dossier.mkdir(parents=True, exist_ok=True)
    (dossier / f"tableau_{nom}.tex").write_text(
        tableau_latex(asr_a, asr_b, titres_des_scenarios(jeu["scenarios"])), encoding="utf-8")
    (dossier / f"synthese_{nom}.tex").write_text(synthese_latex(m_a, m_b), encoding="utf-8")
    graphique_asr(asr_a, asr_b, f"{jeu['titre']} : ASR par scénario", dossier / f"asr_{nom}.png")
    pd.concat([asr_a.assign(version="A"), asr_b.assign(version="B")]).round(1).to_csv(
        dossier / f"metriques_{nom}.csv", index=False)
    return {"A": m_a, "B": m_b}


def main():
    for nom, jeu in JEUX.items():
        m = analyser_jeu(nom, jeu, DOSSIER_FIGURES)
        print(f"\n== {jeu['titre']} ==")
        for version in ("A", "B"):
            v = m[version]
            print(f"  {version} : ASR {v['attaques_reussies']}/{v['attaques']}, "
                  f"canary {v['fuites_canary']}, faux positifs {v['faux_positifs']}/{v['legitimes']}, "
                  f"latence médiane {v['latence_mediane_s']:.1f} s, non jugées {v['erreurs']}")
    print(f"\nFichiers écrits dans {DOSSIER_FIGURES}")


if __name__ == "__main__":
    sys.exit(main())
