"""
Client du modèle local (Ollama).

Deux fonctions :
- appeler_modele() : envoie UNE fois la conversation au modèle ;
- discuter_avec_outils() : la boucle complète quand le modèle utilise des outils.

Comment le modèle utilise un outil :
  1. on lui envoie la conversation + la liste des outils disponibles ;
  2. au lieu de répondre, il peut demander « appelle consulter_fiche_client(C003) » ;
  3. NOTRE code exécute la fonction Python et lui renvoie le résultat ;
  4. il rédige alors sa réponse finale à partir de ce résultat.
Le modèle n'exécute donc jamais rien lui-même : c'est notre code qui décide.
C'est précisément là que la version B ajoutera ses contrôles (moindre privilège).
"""

import json
import time
from dataclasses import dataclass, field
from typing import Callable

import ollama

from app.shared.config import Config


@dataclass
class ReponseLLM:
    texte: str                                         # réponse finale du chatbot
    appels_outils: list = field(default_factory=list)  # [{"nom": ..., "arguments": ..., "resultat": ...}]
    latence_s: float = 0.0                             # temps total, en secondes


def appeler_modele(config: Config, messages: list, outils: list | None = None,
                   graine: int | None = None, options: dict | None = None):
    """
    Un seul aller-retour avec Ollama. Température et graine viennent TOUJOURS
    de la configuration, pour que A et B soient appelés de la même façon.
    « options » (facultatif) : options Ollama en plus, utilisées seulement par
    les protections de la version B (ex. num_predict, taille maximale de réponse).
    La version A ne le fournit pas : son appel au modèle est inchangé.
    """
    client = ollama.Client(host=config.ollama_url)
    return client.chat(
        model=config.modele,
        messages=messages,
        tools=outils,
        options={
            "temperature": config.temperature,
            "seed": config.graine if graine is None else graine,
            **(options or {}),
        },
    )


def discuter_avec_outils(config: Config, messages: list, schemas_outils: list,
                         fonctions_outils: dict[str, Callable],
                         graine: int | None = None, max_tours: int = 3,
                         options: dict | None = None) -> ReponseLLM:
    """
    Boucle « le modèle demande un outil -> on l'exécute -> on lui renvoie le résultat ».

    - schemas_outils : la description des outils envoyée au modèle (nom, paramètres) ;
    - fonctions_outils : {nom de l'outil: fonction Python à exécuter} ;
    - max_tours : limite le nombre d'allers-retours, pour ne pas boucler à l'infini.
    """
    messages = list(messages)  # copie : on ne modifie pas la liste de l'appelant
    appels = []
    debut = time.perf_counter()

    for _ in range(max_tours):
        # Sans « options » (version A), l'appel est exactement celui d'avant
        supplement = {"options": options} if options else {}
        reponse = appeler_modele(config, messages, schemas_outils, graine, **supplement)
        message = reponse.message

        # Pas de demande d'outil : c'est la réponse finale
        if not message.tool_calls:
            return ReponseLLM(message.content or "", appels, time.perf_counter() - debut)

        # On garde dans l'historique la demande d'outil faite par le modèle
        messages.append(message)

        for demande in message.tool_calls:
            nom = demande.function.name
            arguments = dict(demande.function.arguments)

            if nom in fonctions_outils:
                try:
                    resultat = fonctions_outils[nom](**arguments)
                except TypeError as erreur:  # le modèle a inventé de mauvais paramètres
                    resultat = {"erreur": f"paramètres invalides : {erreur}"}
            else:
                resultat = {"erreur": f"outil inconnu : {nom}"}

            appels.append({"nom": nom, "arguments": arguments, "resultat": resultat})
            # On renvoie le résultat au modèle, sous forme de texte JSON
            messages.append({
                "role": "tool",
                "tool_name": nom,
                "content": json.dumps(resultat, ensure_ascii=False),
            })

    # Trop de tours : on s'arrête proprement
    return ReponseLLM("Désolé, je n'ai pas pu terminer votre demande.",
                      appels, time.perf_counter() - debut)
