"""
Interface de démonstration du laboratoire.

Lancement dans Docker : service « ui », puis http://localhost:8501
Lancement local       : streamlit run app/ui/streamlit_app.py

Streamlit relance ce script de haut en bas à CHAQUE interaction
(clic, question...). L'historique est donc gardé dans st.session_state,
une mémoire qui survit à ces relances.
"""

import streamlit as st

from app.shared.config import charger_config
from app.ui import api

CLIENTS = ["C001", "C002", "C003", "C004", "C005", "C006"]
NOMS_VERSIONS = {"A": "🔴 A : vulnérable", "B": "🟢 B : sécurisée"}

st.set_page_config(page_title="Labo sécurité LLM", page_icon="🔒")
canary = charger_config().canary

if "historique" not in st.session_state:
    st.session_state.historique = []  # liste de dictionnaires {role, texte, ...}
if "confirmations" not in st.session_state:
    st.session_state.confirmations = {}  # {id_action: résultat affiché}

# ---------- Barre latérale : réglages ----------
with st.sidebar:
    st.header("Réglages")
    version = st.radio("Version du chatbot", ["A", "B"],
                       format_func=lambda v: NOMS_VERSIONS[v])
    disponible = api.est_disponible(version)
    if not disponible:
        st.warning(f"La version {version} n'est pas encore disponible.")

    id_client = st.selectbox("Client connecté", CLIENTS,
                             help="Identité déclarée au chatbot (scénario A8).")

    if st.button("Effacer la conversation"):
        st.session_state.historique = []

    st.caption("Données 100 % fictives — modèle local — laboratoire isolé.")

# ---------- Zone principale ----------
st.title("Brumelec — assistant client")
st.caption("Démonstration avant / après sécurisation d'une application LLM.")


def afficher_reponse(msg: dict) -> None:
    """Affiche une réponse du chatbot, ses alertes et ses détails techniques."""
    st.markdown(f"**Version {msg['version']}**")
    for alerte in api.detecter_alertes(msg["texte"], canary, msg["outils"]):
        st.error(alerte, icon="🚨")
    st.markdown(msg["texte"])  # le HTML éventuel n'est PAS interprété par Streamlit
    with st.expander("Détails"):
        st.write("**Documents utilisés (RAG) :**", ", ".join(msg["sources"]) or "aucun")
        if msg["outils"]:
            st.write("**Outils appelés :**")
            for appel in msg["outils"]:
                st.code(f"{appel['nom']}({appel['arguments']})", language="python")
                st.caption(api.etat_appel(appel))
        else:
            st.write("**Outils appelés :** aucun")
        if msg.get("bloque"):
            st.write("**Requête bloquée par une protection :** oui")
        st.write(f"**Latence :** {msg['latence_s']:.1f} s")


def afficher_confirmations(msg: dict, numero: int) -> None:
    """
    Version B : une action sensible (remboursement, e-mail) n'est pas exécutée
    tant que le client ne l'a pas confirmée lui-même. Un bouton par action.
    """
    for action in msg.get("a_confirmer", []):
        cle = action["id_action"]
        etat = st.session_state.confirmations.get(cle)
        st.warning(f"Action en attente de votre accord : **{action['nom']}** "
                   f"{action['arguments']}", icon="✋")
        if etat:
            st.success(etat)
        elif st.button("Confirmer cette action", key=f"confirmer-{numero}-{cle}"):
            try:
                resultat = api.confirmer_action(msg["version"], cle, msg["id_client"])
            except Exception as erreur:
                resultat = {"refuse": str(erreur)}
            st.session_state.confirmations[cle] = (
                f"Refusé : {resultat['refuse']}" if "refuse" in resultat
                else f"Fait : {resultat.get('statut', 'action exécutée')}")
            st.rerun()


# Réaffiche l'historique (le script est relancé à chaque interaction)
for numero, msg in enumerate(st.session_state.historique):
    with st.chat_message(msg["role"]):
        if msg["role"] == "user":
            st.markdown(msg["texte"])
        else:
            afficher_reponse(msg)
            afficher_confirmations(msg, numero)

question = st.chat_input("Posez votre question…", disabled=not disponible)
if question:
    st.session_state.historique.append({"role": "user", "texte": question})
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        try:
            with st.spinner(f"La version {version} réfléchit…"):
                r = api.envoyer_question(version, question, id_client)
        except Exception as erreur:
            st.error(f"Impossible de joindre la version {version} : {erreur}")
        else:
            msg = {"role": "assistant", "version": version, "texte": r["reponse"],
                   "sources": r["sources"], "outils": r["outils_appeles"],
                   "latence_s": r["latence_s"], "bloque": r.get("bloque", False),
                   "a_confirmer": r.get("a_confirmer", []), "id_client": id_client}
            st.session_state.historique.append(msg)
            afficher_reponse(msg)
            afficher_confirmations(msg, len(st.session_state.historique) - 1)
