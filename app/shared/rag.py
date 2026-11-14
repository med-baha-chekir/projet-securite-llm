"""
RAG (Retrieval-Augmented Generation) : retrouver les passages de documents
utiles pour répondre à une question, puis les donner au modèle.

Fonctionnement :
  1. découpage : chaque document est coupé en morceaux (un par section « ## ») ;
  2. indexation : chaque morceau est transformé en vecteur (embedding) par le
     modèle nomic-embed-text, puis rangé dans ChromaDB ;
  3. recherche : la question est aussi transformée en vecteur, et ChromaDB
     renvoie les morceaux dont le vecteur est le plus proche (= sens proche).

Les morceaux sont renvoyés BRUTS, sans aucun nettoyage : un document piégé
arrive donc tel quel jusqu'au modèle (scénario A5). Le nettoyage et la
délimitation des documents sont des protections de la version B.
"""

from pathlib import Path

import chromadb
from chromadb.config import Settings
from chromadb.utils.embedding_functions import OllamaEmbeddingFunction

from app.shared.config import Config


def decouper_document(texte: str) -> list[str]:
    """
    Coupe un document Markdown en morceaux, un par section « ## ».
    Le titre du document (ligne « # ... ») est recopié au début de chaque
    morceau, pour que chaque morceau garde son contexte.
    Un document sans section « ## » reste en un seul morceau.
    """
    lignes = texte.strip().splitlines()
    titre = lignes[0] if lignes and lignes[0].startswith("# ") else ""

    morceaux, courant = [], []
    for ligne in lignes:
        if ligne.startswith("## ") and courant:
            morceaux.append("\n".join(courant).strip())
            courant = [titre] if titre else []
        courant.append(ligne)
    if courant:
        morceaux.append("\n".join(courant).strip())

    # Si le premier morceau ne contient que le titre et l'avertissement, on l'enlève
    if len(morceaux) > 1 and "## " not in morceaux[0]:
        morceaux = morceaux[1:]
    return morceaux


class BaseDocumentaire:
    """Base vectorielle en mémoire, reconstruite à chaque démarrage (6 documents : c'est rapide)."""

    def __init__(self, config: Config):
        # Base en mémoire, télémétrie désactivée : aucune donnée envoyée à l'extérieur
        self.client = chromadb.EphemeralClient(settings=Settings(anonymized_telemetry=False))
        self.collection = self.client.get_or_create_collection(
            name="documents_brumelec",
            embedding_function=OllamaEmbeddingFunction(
                url=config.ollama_url, model_name=config.modele_embeddings),
            metadata={"hnsw:space": "cosine"},  # distance cosinus : 0 = sens identique
        )
        self.dossier_documents = config.dossier_documents

    def indexer(self) -> int:
        """Indexe tous les fichiers .md du dossier documents. Renvoie le nombre de morceaux."""
        ids, textes, sources = [], [], []
        for fichier in sorted(Path(self.dossier_documents).glob("*.md")):
            for i, morceau in enumerate(decouper_document(fichier.read_text(encoding="utf-8"))):
                ids.append(f"{fichier.stem}-{i}")
                textes.append(morceau)
                sources.append({"source": fichier.name})
        # upsert = ajoute, ou remplace si l'identifiant existe déjà (relance sans doublon)
        self.collection.upsert(ids=ids, documents=textes, metadatas=sources)
        return len(ids)

    def rechercher(self, question: str, k: int = 3) -> list[dict]:
        """Renvoie les k morceaux les plus proches de la question."""
        resultat = self.collection.query(query_texts=[question], n_results=k)
        return [
            {"source": meta["source"], "texte": texte, "distance": round(dist, 3)}
            for texte, meta, dist in zip(resultat["documents"][0],
                                         resultat["metadatas"][0],
                                         resultat["distances"][0])
        ]
