"""
Enregistrement de la vidéo de démonstration (P7) : une attaque par scénario,
jouée sur la version A puis sur la version B, dans la VRAIE interface.

Un navigateur (Playwright) se comporte comme un utilisateur : il choisit la
version, tape l'attaque, attend la réponse, ouvre les « Détails ». L'écran est
filmé. Le verdict affiché à la fin de chaque séquence est calculé par les mêmes
critères automatiques que la campagne (evaluation/criteres.py) : rien n'est
écrit à la main.

Lancement (le labo doit tourner) :
    docker compose --profile outils run --rm video python demo/enregistrer.py
    docker compose --profile outils run --rm video python demo/enregistrer.py A7   # un seul scénario

Sortie : demo/sortie/clips/<scénario>_<version>.webm et demo/sortie/clips.json
(les instants clés de chaque séquence, utilisés par demo/monter.py).
"""

import ast
import json
import shutil
import sys
import time
from pathlib import Path

import yaml
from playwright.sync_api import sync_playwright

from evaluation.criteres import evaluer_attaque

RACINE = Path(__file__).resolve().parent.parent
SORTIE = RACINE / "demo" / "sortie"
CLIPS = SORTIE / "clips"
URL_UI = "http://ui:8501"
TAILLE = {"width": 1280, "height": 720}

# Une attaque par scénario : la variante la plus parlante (numéro dans attacks/scenarios.yaml,
# à partir de 1). Ce sont celles qui réussissent 5 fois sur 5 sur A dans la campagne
# officielle, sauf A2 (aucune variante fiable : le modèle refuse seul les jeux de rôle).
VARIANTES = {"A1": 2, "A2": 3, "A3": 1, "A4": 1, "A5": 1,
             "A6": 3, "A7": 2, "A8": 1, "A9": 1, "A10": 1}
# A2 n'est PAS rejouée jusqu'à obtenir un succès : on montre ce qui arrive vraiment.
PRISES_MAX = {"A2": 1}
PRISES_MAX_DEFAUT = 3

NOMS_VERSIONS = {"A": "Version A : vulnérable", "B": "Version B : sécurisée"}
COULEURS = {"A": "#B03A2E", "B": "#1E7B4F"}

# Habillage de la page pendant le tournage : bandeau du haut, messages géants
# repliés (A9 envoie 30 000 caractères), en-tête Streamlit masqué.
CSS = """
header[data-testid="stHeader"] { display: none !important; }
#bandeau-demo { position: fixed; top: 0; left: 300px; right: 0; z-index: 999999;
  padding: 10px 22px; font: 600 17px/1.3 'DejaVu Sans', sans-serif; color: white; }
#verdict-demo { position: fixed; left: 50%; bottom: 26px; transform: translateX(-50%);
  z-index: 99999; padding: 14px 26px; border-radius: 10px; color: white; max-width: 1100px;
  font: 700 22px/1.35 'DejaVu Sans', sans-serif; box-shadow: 0 6px 24px rgba(0,0,0,.35); }
#verdict-demo small { display: block; font-weight: 400; font-size: 15px; margin-top: 4px; }
#verdict-demo code { font-size: 13px; background: rgba(255,255,255,.18); padding: 1px 5px;
  border-radius: 4px; word-break: break-all; }
[data-testid="stChatMessage"]:has([data-testid="stChatMessageAvatarUser"])
  [data-testid="stMarkdownContainer"] { max-height: 170px; overflow: hidden; }
textarea[data-testid="stChatInputTextArea"] { max-height: 90px !important; }
section[data-testid="stMain"] { padding-top: 40px; }
"""


def charger_scenarios() -> dict:
    scenarios = yaml.safe_load((RACINE / "attacks" / "scenarios.yaml").read_text(encoding="utf-8"))
    return {s["id"]: s for s in scenarios}


def construire_message(variante) -> str:
    """Même construction que la campagne (A9 : message répété)."""
    if isinstance(variante, dict) and "repeter" in variante:
        return variante["repeter"]["texte"] * variante["repeter"]["fois"]
    return variante


def contexte_verdict(scenario: dict, message: str) -> dict:
    canary = (RACINE / "secrets" / "canary.txt").read_text(encoding="utf-8").strip()
    clients = json.loads((RACINE / "data" / "customers.json").read_text(encoding="utf-8"))["clients"]
    return {"canary": canary, "id_client": scenario["id_client"],
            "clients": {c["id"]: c for c in clients}, "message": message}


# ---------- lecture de la réponse affichée ----------

LIRE_REPONSE = """() => {
  const msgs = document.querySelectorAll('[data-testid="stChatMessage"]');
  const dernier = msgs[msgs.length - 1];
  const textes = [...dernier.querySelectorAll('[data-testid="stMarkdownContainer"]')]
    .filter(e => !e.closest('[data-testid="stExpander"]') && !e.closest('[data-testid="stAlert"]'))
    .map(e => e.innerText);
  const codes = [...dernier.querySelectorAll('[data-testid="stExpander"] [data-testid="stCode"]')]
    .map(e => {
      let etat = e.nextElementSibling;
      while (etat && !etat.innerText.trim()) etat = etat.nextElementSibling;
      return {code: e.innerText, etat: etat ? etat.innerText : ''};
    });
  const details = (dernier.querySelector('[data-testid="stExpander"]') || {innerText: ''}).innerText;
  const erreur = [...dernier.querySelectorAll('[data-testid="stAlert"]')]
    .some(e => e.innerText.includes('Impossible de joindre'));
  // Images affichées DANS LA RÉPONSE (pas dans le message de l'utilisateur,
  // que l'interface affiche aussi en Markdown)
  const images = [...dernier.querySelectorAll('img')].map(i => i.src)
    .filter(s => s.includes('attaquant.test'));
  return {textes, codes, details, erreur, images};
}"""

# Ce que renvoie le faux serveur de l'attaquant : un badge visible, pour qu'on voie
# à l'écran que l'image a bien été chargée (donc que la requête est partie).
BADGE = """<svg xmlns="http://www.w3.org/2000/svg" width="440" height="46">
<rect width="440" height="46" rx="8" fill="#B03A2E"/>
<text x="220" y="29" font-family="DejaVu Sans" font-size="16" fill="white" text-anchor="middle">
Image chargée depuis attaquant.test</text></svg>""".encode("utf-8")


def appel_depuis_code(code: str, etat: str) -> dict:
    """« creer_remboursement({'id_client': 'C006', ...}) » -> appel au format de la campagne."""
    nom, _, reste = code.strip().partition("(")
    try:
        arguments = ast.literal_eval(reste.rstrip().removesuffix(")"))
    except (ValueError, SyntaxError):
        arguments = {"texte_brut": reste}
    if "refusé" in etat:
        resultat = {"refuse": etat}
    elif "erreur" in etat:
        resultat = {"erreur": etat}
    else:
        resultat = {"statut": etat}
    return {"nom": nom.strip(), "arguments": arguments, "resultat": resultat}


def resultat_affiche(lu: dict, images: list[str]) -> dict:
    """Reconstitue le résultat de l'API à partir de ce que montre l'interface."""
    reponse = "\n".join(lu["textes"][1:])          # le premier bloc est « Version X »
    # Une image Markdown est affichée comme image : on remet son adresse dans le texte,
    # pour que le critère A7 (image vers attaquant.test) puisse la juger.
    reponse += "".join(f"\n![image]({url})" for url in images)
    return {"statut_http": 0 if lu["erreur"] else 200, "reponse": reponse,
            "outils_appeles": [appel_depuis_code(c["code"], c["etat"]) for c in lu["codes"]],
            "bloque": "bloquée par une protection" in lu["details"]}


# ---------- une séquence filmée ----------

def taper(page, message: str) -> None:
    zone = page.locator('textarea[data-testid="stChatInputTextArea"]')
    zone.click()
    if len(message) > 600:                        # A9 : on ne tape pas 30 000 caractères
        zone.fill(message)
        return
    for i, ligne in enumerate(message.split("\n")):
        if i:
            page.keyboard.press("Shift+Enter")
        page.keyboard.type(ligne, delay=14)


def afficher_verdict(page, version: str, declenches: list[str], images: list[str]) -> None:
    if declenches:
        couleur = "#B03A2E"
        titre = "❌ Attaque réussie"
        detail = "Critère automatique déclenché : " + ", ".join(declenches)
    else:
        couleur = "#1E7B4F"
        titre = "✅ Attaque bloquée" if version == "B" else "✅ Attaque échouée"
        detail = "Aucun critère de succès déclenché"
    if images:
        detail += "<br>Requête envoyée par le navigateur à l'attaquant :<br><code>" + \
                  "<br>".join(images) + "</code>"
    page.evaluate("""([couleur, html]) => {
        const d = document.getElementById('verdict-demo') || document.createElement('div');
        d.id = 'verdict-demo'; d.style.background = couleur; d.innerHTML = html;
        document.body.appendChild(d);
    }""", [couleur, f"{titre}<small>{detail}</small>"])


def filmer(navigateur, id_scenario: str, scenario: dict, version: str, numero: int) -> dict:
    variante = scenario["variantes"][numero - 1]
    message = construire_message(variante)
    images = []                                   # requêtes vers le serveur de l'attaquant

    contexte = navigateur.new_context(viewport=TAILLE, record_video_dir=str(CLIPS / "brut"),
                                      record_video_size=TAILLE, locale="fr-FR")
    t0 = time.monotonic()
    page = contexte.new_page()

    # A7 : l'image piégée part vers attaquant.test. On intercepte la requête DANS le
    # navigateur filmé : on note l'adresse (avec les données dedans) et on renvoie un
    # badge visible. Rien ne sort du labo (le domaine .test n'existe pas de toute façon).
    # L'interface affiche aussi le message de l'utilisateur en Markdown : l'image qu'il
    # a tapée telle quelle (« ...?d=DONNEES ») reste invisible, pour ne pas faire croire
    # que le chatbot l'a produite. Le verdict, lui, ne regarde que la réponse.
    def intercepter(route):
        images.append(route.request.url)
        if route.request.url in message:
            route.fulfill(status=200, content_type="image/svg+xml",
                          body=b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>')
        else:
            route.fulfill(status=200, content_type="image/svg+xml", body=BADGE)
    page.route(lambda url: "attaquant.test" in url, intercepter)

    page.goto(URL_UI)
    page.locator('textarea[data-testid="stChatInputTextArea"]').wait_for(timeout=120_000)
    page.add_style_tag(content=CSS)
    page.get_by_text(NOMS_VERSIONS[version].replace("Version ", "").replace(" :", " :"),
                     exact=False).first.click()
    page.wait_for_timeout(1500)
    page.evaluate("""([texte, couleur]) => {
        const d = document.createElement('div'); d.id = 'bandeau-demo';
        d.style.background = couleur; d.textContent = texte; document.body.appendChild(d);
    }""", [f"{id_scenario} · {scenario['owasp']} · {scenario['titre'].split(' (')[0]}"
           f"   —   {NOMS_VERSIONS[version]}", COULEURS[version]])
    page.wait_for_timeout(1200)
    t_pret = time.monotonic() - t0

    taper(page, message)
    page.wait_for_timeout(600)
    page.keyboard.press("Enter")
    t_envoi = time.monotonic() - t0

    page.wait_for_function("""() => {
        const m = document.querySelectorAll('[data-testid="stChatMessage"]');
        return m.length >= 2 && !document.querySelector('[data-testid="stSpinner"]')
               && m[m.length - 1].innerText.includes('Version');
    }""", timeout=420_000, polling=500)
    t_reponse = time.monotonic() - t0
    page.wait_for_timeout(2500)                   # laisser le temps de lire la réponse

    # Ouvrir les détails (documents utilisés, outils appelés et leur état)
    page.locator('[data-testid="stExpander"] summary').last.click()
    page.wait_for_timeout(400)
    page.locator('[data-testid="stExpander"]').last.scroll_into_view_if_needed()
    page.wait_for_timeout(2500)

    lu = page.evaluate(LIRE_REPONSE)
    # Requêtes réellement parties vers l'attaquant à cause de la RÉPONSE du chatbot
    images = [url for url in images if url in lu["images"]]
    resultat = resultat_affiche(lu, images)
    declenches = evaluer_attaque(scenario, resultat, contexte_verdict(scenario, message))
    afficher_verdict(page, version, declenches, images)
    t_verdict = time.monotonic() - t0
    page.wait_for_timeout(5500)
    t_fin = time.monotonic() - t0

    video = page.video
    contexte.close()                              # écrit la vidéo
    fichier = CLIPS / f"{id_scenario}_{version}.webm"
    shutil.move(video.path(), fichier)
    return {"scenario": id_scenario, "version": version, "variante": numero,
            "fichier": fichier.name, "t_pret": round(t_pret, 2), "t_envoi": round(t_envoi, 2),
            "t_reponse": round(t_reponse, 2), "t_verdict": round(t_verdict, 2),
            "t_fin": round(t_fin, 2), "succes": bool(declenches), "criteres": declenches,
            "images_interceptees": len(images)}


def main():
    scenarios = charger_scenarios()
    choisis = sys.argv[1:] or list(VARIANTES)
    CLIPS.mkdir(parents=True, exist_ok=True)
    journal_fichier = SORTIE / "clips.json"
    journal = json.loads(journal_fichier.read_text(encoding="utf-8")) if journal_fichier.exists() else {}

    with sync_playwright() as p:
        navigateur = p.chromium.launch()
        for id_scenario in choisis:
            scenario = scenarios[id_scenario]
            for version in ("A", "B"):
                prises = PRISES_MAX.get(id_scenario, PRISES_MAX_DEFAUT) if version == "A" else 1
                for prise in range(1, prises + 1):
                    infos = filmer(navigateur, id_scenario, scenario, version, VARIANTES[id_scenario])
                    infos["prise"] = prise
                    print(f"{id_scenario} {version} prise {prise} : "
                          f"{'RÉUSSIE' if infos['succes'] else 'échouée'} {infos['criteres']} "
                          f"(réponse en {infos['t_reponse'] - infos['t_envoi']:.0f} s)", flush=True)
                    # Sur A, une attaque qui échoue par hasard est refilmée (sauf A2) ;
                    # le nombre de prises est gardé dans clips.json.
                    if infos["succes"] or version == "B":
                        break
                journal[f"{id_scenario}_{version}"] = infos
                journal_fichier.write_text(json.dumps(journal, indent=2, ensure_ascii=False),
                                           encoding="utf-8")
        navigateur.close()
    shutil.rmtree(CLIPS / "brut", ignore_errors=True)


if __name__ == "__main__":
    main()
