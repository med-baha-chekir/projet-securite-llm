# ============================================================
#  Image commune aux versions A et B (seule la commande change)
# ============================================================
FROM python:3.12-slim

WORKDIR /projet
# Permet d'importer « app.shared... » quel que soit le script lancé (Streamlit)
ENV PYTHONPATH=/projet

# 1. Dépendances d'abord : cette étape reste en cache tant que
#    requirements.txt ne change pas (reconstruction plus rapide)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 2. Code et données fictives
COPY app/ app/
COPY data/ data/

# Le secret (canary) n'est PAS dans l'image : il est fourni au
# lancement par docker-compose depuis le fichier .env.

# Utilisateur sans privilèges (bonne pratique : jamais root)
RUN useradd --create-home labo && mkdir -p logs && chown labo logs
USER labo
