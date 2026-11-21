"""
Montage de la vidéo de démonstration (P7), à partir des séquences filmées par
demo/enregistrer.py.

Structure : carte d'introduction, puis pour chaque scénario une carte de titre,
la séquence sur A et la séquence sur B, puis une carte de conclusion.
Les temps d'attente du modèle sont accélérés (et l'accélération est écrite à
l'écran). Les chiffres des cartes viennent des fichiers de résultats, jamais
saisis à la main.

Lancement :
    docker compose --profile outils run --rm video python demo/monter.py
Sortie : demo/sortie/demo_avant_apres.mp4
"""

import csv
import html
import json
import subprocess
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright

from demo.enregistrer import VARIANTES, construire_message

RACINE = Path(__file__).resolve().parent.parent
SORTIE = RACINE / "demo" / "sortie"
CLIPS = SORTIE / "clips"
TRAVAIL = SORTIE / "montage"
FINAL = SORTIE / "demo_avant_apres.mp4"
POLICE = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
IPS = 30                                    # images par seconde
ATTENTE_MAX_S = 2.5                         # durée à l'écran d'une attente accélérée

# ---------- chiffres de la campagne (générés par evaluation/analyse.py) ----------

def asr_campagne() -> dict:
    """{(scénario, version): (réussies, total, asr)} depuis metriques_officiel.csv."""
    lignes = csv.DictReader(open(RACINE / "results" / "figures" / "metriques_officiel.csv",
                                 encoding="utf-8"))
    return {(l["id"], l["version"]): (int(l["reussies"]), int(l["total"]), float(l["asr"]))
            for l in lignes}


# ---------- cartes (rendues en HTML puis capturées en image) ----------

STYLE = """
body { margin: 0; width: 1280px; height: 720px; display: flex; flex-direction: column;
  justify-content: center; padding: 0 90px; box-sizing: border-box; background: #1F3A5F;
  color: white; font-family: 'DejaVu Sans', sans-serif; }
h1 { font-size: 46px; margin: 0 0 18px; } h2 { font-size: 26px; font-weight: 400; margin: 0 0 26px;
  color: #CFE0F5; }
p, li { font-size: 21px; line-height: 1.5; margin: 4px 0; }
.etiquette { display: inline-block; background: rgba(255,255,255,.15); padding: 4px 12px;
  border-radius: 6px; font-size: 20px; margin-bottom: 18px; }
.attaque { background: rgba(0,0,0,.25); border-left: 5px solid #F2B8B0; padding: 14px 18px;
  font-family: 'DejaVu Sans Mono', monospace; font-size: 17px; line-height: 1.45;
  white-space: pre-wrap; margin: 10px 0 20px; }
.chiffres { display: flex; gap: 28px; } .chiffres div { padding: 10px 18px; border-radius: 8px;
  font-size: 21px; } .a { background: #B03A2E; } .b { background: #1E7B4F; }
table { border-collapse: collapse; font-size: 20px; } td, th { padding: 6px 18px; text-align: left; }
th { color: #CFE0F5; font-weight: 400; } .petit { font-size: 16px; color: #CFE0F5; margin-top: 22px; }
"""


def carte(page, nom: str, corps: str) -> Path:
    fichier = TRAVAIL / f"{nom}.png"
    page.set_content(f"<html><head><meta charset='utf-8'><style>{STYLE}</style></head>"
                     f"<body>{corps}</body></html>")
    page.screenshot(path=str(fichier))
    return fichier


def corps_introduction() -> str:
    return """
<div class="etiquette">Projet cybersécurité · démonstration avant / après</div>
<h1>Sécurité d'un chatbot LLM</h1>
<h2>Les mêmes attaques sur la version A (vulnérable) puis sur la version B (sécurisée)</h2>
<ul>
<li>Même modèle local (llama3.1:8b), mêmes données fictives, mêmes attaques</li>
<li>Une attaque par scénario, de A1 à A10 (OWASP Top 10 LLM 2025)</li>
<li>Le verdict affiché est calculé par les critères automatiques de la campagne</li>
<li>Les temps de réflexion du modèle sont accélérés à l'écran</li>
</ul>"""


def corps_scenario(scenario: dict, asr: dict) -> str:
    variante = scenario["variantes"][VARIANTES[scenario["id"]] - 1]
    message = construire_message(variante)
    if len(message) > 600:                       # A9 : on décrit le message au lieu de l'afficher
        texte = (f"« {variante['repeter']['texte'].strip()} » répété {variante['repeter']['fois']} fois"
                 f"\n→ un message de {len(message):,} caractères".replace(",", " "))
    else:
        texte = message if len(message) < 330 else message[:330] + "…"
    ra, ta, pa = asr[(scenario["id"], "A")]
    rb, tb, pb = asr[(scenario["id"], "B")]
    return f"""
<div class="etiquette">Scénario {scenario['id']} · {html.escape(scenario['owasp'])}</div>
<h1>{html.escape(scenario['titre'])}</h1>
<p>{html.escape(" ".join(scenario['objectif'].split()))}</p>
<div class="attaque">{html.escape(texte)}</div>
<div class="chiffres">
  <div class="a">Campagne, version A : {ra}/{ta} ({pa:.0f} %)</div>
  <div class="b">Campagne, version B : {rb}/{tb} ({pb:.0f} %)</div>
</div>"""


def corps_conclusion(asr: dict, journal: dict) -> str:
    def total(version):
        lignes = [v for (s, ver), v in asr.items() if ver == version]
        r, t = sum(l[0] for l in lignes), sum(l[1] for l in lignes)
        return f"{r}/{t} ({100 * r / t:.0f} %)"
    tournage = {v: sum(1 for k, c in journal.items() if k.endswith("_" + v) and c["succes"])
                for v in ("A", "B")}
    remarques = []
    echecs_a = [c["scenario"] for k, c in journal.items() if k.endswith("_A") and not c["succes"]]
    if echecs_a:
        remarques.append("Attaques échouées sur A pendant le tournage : " + ", ".join(echecs_a)
                         + " (le modèle refuse parfois seul).")
    refaites = [f"{c['scenario']} ({c['prise']} prises)" for k, c in journal.items()
                if c.get("prise", 1) > 1]
    if refaites:
        remarques.append("Prises refaites sur A après un échec dû au hasard : " + ", ".join(refaites) + ".")
    return f"""
<h1>Résultat</h1>
<table>
<tr><th></th><th>Version A</th><th>Version B</th></tr>
<tr><td>Ce tournage (1 attaque par scénario)</td><td>{tournage['A']}/10 réussies</td>
    <td>{tournage['B']}/10 réussies</td></tr>
<tr><td>Campagne complète (155 tentatives)</td><td>{total('A')}</td><td>{total('B')}</td></tr>
</table>
<p style="margin-top:26px">Aucune protection ne suffit seule : c'est leur empilement qui protège.</p>
<p>Sur des attaques jamais vues, B laisse encore passer 10 % des attaques : la sécurité d'un LLM se mesure, elle ne se suppose pas.</p>
<p class="petit">{"<br>".join(html.escape(r) for r in remarques)}</p>"""


# ---------- vidéo ----------

def ffmpeg(*arguments: str) -> None:
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", *arguments], check=True)


def duree(fichier: Path) -> float:
    sortie = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration",
                             "-of", "csv=p=0", str(fichier)], capture_output=True, text=True, check=True)
    return float(sortie.stdout.strip())


ENCODAGE = ["-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-pix_fmt", "yuv420p",
            "-r", str(IPS)]


def video_de_carte(image: Path, secondes: float) -> Path:
    fichier = image.with_suffix(".mp4")
    ffmpeg("-loop", "1", "-t", str(secondes), "-i", str(image),
           "-vf", f"fps={IPS},format=yuv420p", *ENCODAGE, str(fichier))
    return fichier


def video_de_sequence(infos: dict) -> Path:
    """Coupe le chargement de la page et accélère l'attente de la réponse."""
    source = CLIPS / infos["fichier"]
    # La vidéo de Playwright se termine à la fermeture du navigateur : on aligne
    # les instants mesurés sur la FIN de la vidéo.
    decalage = duree(source) - infos["t_fin"]
    debut = max(0.0, infos["t_pret"] + decalage - 0.3)
    fin_frappe = infos["t_envoi"] + decalage + 1.0
    reponse = infos["t_reponse"] + decalage
    attente = reponse - fin_frappe
    fichier = TRAVAIL / f"{source.stem}.mp4"

    if attente < 2 * ATTENTE_MAX_S:               # réponse rapide : rien à accélérer
        filtre = f"[0:v]trim={debut}:{duree(source)},setpts=PTS-STARTPTS[v]"
    else:
        facteur = attente / ATTENTE_MAX_S
        reel = infos["t_reponse"] - infos["t_envoi"]
        texte = f"Attente de la réponse du modèle  {reel:.0f} s  accélérée x{facteur:.0f}"
        filtre = (
            f"[0:v]trim={debut}:{fin_frappe},setpts=PTS-STARTPTS[a];"
            f"[0:v]trim={fin_frappe}:{reponse},setpts=(PTS-STARTPTS)/{facteur:.3f},"
            f"drawtext=fontfile={POLICE}:text='{texte}':fontsize=26:fontcolor=white:"
            f"box=1:boxcolor=black@0.65:boxborderw=14:x=(w-text_w)/2+150:y=h-110[b];"
            f"[0:v]trim={reponse},setpts=PTS-STARTPTS[c];"
            f"[a][b][c]concat=n=3:v=1:a=0[v]")
    ffmpeg("-i", str(source), "-filter_complex", filtre, "-map", "[v]", "-an", *ENCODAGE,
           str(fichier))
    return fichier


def main():
    TRAVAIL.mkdir(parents=True, exist_ok=True)
    journal = json.loads((SORTIE / "clips.json").read_text(encoding="utf-8"))
    scenarios = {s["id"]: s for s in yaml.safe_load(
        (RACINE / "attacks" / "scenarios.yaml").read_text(encoding="utf-8"))}
    asr = asr_campagne()

    morceaux = []
    with sync_playwright() as p:
        navigateur = p.chromium.launch()
        page = navigateur.new_page(viewport={"width": 1280, "height": 720})
        morceaux.append(video_de_carte(carte(page, "00_intro", corps_introduction()), 9))
        for id_scenario in VARIANTES:
            if f"{id_scenario}_A" not in journal or f"{id_scenario}_B" not in journal:
                print(f"{id_scenario} : séquence manquante, ignoré")
                continue
            image = carte(page, f"{id_scenario}_titre", corps_scenario(scenarios[id_scenario], asr))
            morceaux.append(video_de_carte(image, 6))
            for version in ("A", "B"):
                morceaux.append(video_de_sequence(journal[f"{id_scenario}_{version}"]))
            print(f"{id_scenario} monté", flush=True)
        morceaux.append(video_de_carte(carte(page, "99_fin", corps_conclusion(asr, journal)), 12))
        navigateur.close()

    liste = TRAVAIL / "liste.txt"
    liste.write_text("".join(f"file '{m.name}'\n" for m in morceaux), encoding="utf-8")
    ffmpeg("-f", "concat", "-safe", "0", "-i", str(liste), "-c", "copy",
           "-movflags", "+faststart", str(FINAL))
    print(f"Vidéo : {FINAL.relative_to(RACINE)} ({duree(FINAL) / 60:.1f} min)")


if __name__ == "__main__":
    main()
