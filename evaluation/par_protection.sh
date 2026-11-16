#!/bin/sh
# ============================================================
#  Analyse par protection (P6) : la version B est rejouée avec UNE SEULE
#  protection activée à la fois, sur les attaques officielles A1 à A10.
#
#  Le code de B ne change pas : seuls les interrupteurs PROTECTION_* changent.
#  Mêmes attaques, mêmes graines, même modèle que les campagnes officielles.
#
#  Lancement, depuis la racine du projet (plusieurs heures) :
#      sh evaluation/par_protection.sh            # toutes les configurations
#      sh evaluation/par_protection.sh outils     # une seule configuration
#  Réglage : REPETITIONS=3 (défaut). Relancer le script reprend là où il s'est
#  arrêté (option --reprendre de la campagne).
#
#  Résultats : results/par_protection/<configuration>/campagne_B_*.csv
#  (le fichier le plus récent de chaque dossier fait foi).
# ============================================================

REPETITIONS="${REPETITIONS:-3}"
SORTIE="${SORTIE:-results/par_protection}"
# Essai rapide : SCENARIOS=A6 SORTIE=results/essai sh evaluation/par_protection.sh outils
if [ -n "$SCENARIOS" ]; then filtre="--scenarios $SCENARIOS"; else filtre=""; fi

# Les 13 protections mesurées. « journal_masque » reste TOUJOURS activée : elle
# ne change pas le résultat d'une attaque, et les journaux restent ainsi masqués.
PROTECTIONS="prompt_durci taille_max filtre_injection classifieur documents outils confirmation debit taille_reponse minimisation sortie_secrets sortie_donnees sortie_html"

# « aucune » = témoin : B sans protection doit se comporter comme A.
CONFIGURATIONS="${*:-aucune $PROTECTIONS}"

majuscules() { echo "$1" | tr '[:lower:]' '[:upper:]'; }

# Exporte les 13 interrupteurs : tous à 0, sauf la protection demandée
regler() {
    for p in $PROTECTIONS; do
        if [ "$p" = "$1" ]; then valeur=1; else valeur=0; fi
        export "PROTECTION_$(majuscules "$p")=$valeur"
    done
    export PROTECTION_JOURNAL_MASQUE=1 SECRET_DANS_PROMPT=0
}

# À la fin (même après une erreur ou Ctrl+C) : B retrouve toutes ses protections
restaurer() {
    echo "=== Retour à la configuration normale de B (toutes les protections) ==="
    for p in $PROTECTIONS; do unset "PROTECTION_$(majuscules "$p")"; done
    unset PROTECTION_JOURNAL_MASQUE SECRET_DANS_PROMPT
    docker compose up -d --wait app-secure
}
trap restaurer EXIT

for config in $CONFIGURATIONS; do
    echo "=== CONFIGURATION : $config ($(date '+%d/%m %H:%M')) ==="
    case " aucune $PROTECTIONS " in
        *" $config "*) ;;
        *) echo "Configuration inconnue : $config"; exit 1 ;;
    esac

    # Ollama est redémarré entre deux configurations : une réponse géante encore
    # en cours de génération (A9) ne doit pas bloquer la configuration suivante
    docker compose restart ollama > /dev/null 2>&1
    docker compose up -d --wait ollama > /dev/null 2>&1
    regler "$config"
    docker compose up -d --wait app-secure > /dev/null 2>&1 || { echo "B ne démarre pas"; exit 1; }

    # Vérification : B annonce exactement la configuration voulue sur /sante
    actives=$(docker compose exec -T app-secure python -c "import json, urllib.request; print(' '.join(sorted(json.load(urllib.request.urlopen('http://localhost:8000/sante'))['protections'])))" | tr -d '\r')
    if [ "$config" = "aucune" ]; then attendues="journal_masque"
    else attendues=$(printf '%s\n' "$config" journal_masque | sort | tr '\n' ' ' | sed 's/ $//'); fi
    if [ "$actives" != "$attendues" ]; then
        echo "ERREUR : B annonce [$actives] au lieu de [$attendues]"; exit 1
    fi
    echo "B annonce : $actives"

    # La pause de 3 s ne sert que si la limite de débit est active
    if [ "$config" = "debit" ]; then pause="--pause 3"; else pause=""; fi
    # Reprise : s'il existe déjà un fichier pour cette configuration, on le complète
    dernier=$(ls "$SORTIE/$config"/campagne_B_*.csv 2> /dev/null | tail -1)
    if [ -n "$dernier" ]; then reprise="--reprendre $dernier"; else reprise=""; fi

    docker compose --profile outils run --rm campagne --version B --sans-benin \
        --repetitions "$REPETITIONS" --sortie "$SORTIE/$config" $pause $reprise $filtre 2>&1 | tail -16
done
