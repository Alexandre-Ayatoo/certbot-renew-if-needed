#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_TAG="remove-domain-management"

DOMAIN="${1:-}"
ACTION="${2:-}"

readonly NGINX_DIRS=(
    "/etc/nginx/sites-enabled"
    "/etc/nginx/sites-available"
    "/etc/nginx/conf.d"
)

readonly LE_DIR="/etc/letsencrypt"

BACKUP=""
NGINX_MATCHES=()
CERTBOT_CERTIFICATES=()

###############################################################################
# Journalisation
###############################################################################

log() {
    local level="$1"
    shift

    local message="$*"
    local priority="user.notice"

    case "$level" in
        INFO)
            priority="user.info"
            ;;
        WARNING)
            priority="user.warning"
            ;;
        ERROR)
            priority="user.err"
            ;;
        SUCCESS)
            priority="user.notice"
            ;;
        DEBUG)
            priority="user.debug"
            ;;
    esac

    printf '[%s] %s\n' "$level" "$message"
    logger \
        --tag "$LOG_TAG" \
        --priority "$priority" \
        -- "$message"
}

die() {
    log ERROR "$*"
    exit 1
}

on_error() {
    local exit_code=$?
    local line_number="${BASH_LINENO[0]:-inconnue}"
    local command="${BASH_COMMAND:-inconnue}"

    log ERROR \
        "Erreur inattendue ligne=${line_number} code=${exit_code} commande=${command}"

    exit "$exit_code"
}

trap on_error ERR

###############################################################################
# Vérifications
###############################################################################

show_usage() {
    echo "Usage : $SCRIPT_NAME domaine.tld [--force]"
    echo
    echo "Domaines gérés détectés :"

    find "$LE_DIR/live" \
        -mindepth 1 \
        -maxdepth 1 \
        -type d \
        -printf '%f\n' 2>/dev/null \
        | grep -v -- '-000' \
        | sort || true
}

validate_domain() {
    if [[ -z "$DOMAIN" ]]; then
        show_usage
        exit 1
    fi

    if [[ "$DOMAIN" == -* ]]; then
        die "Nom de domaine invalide : $DOMAIN"
    fi

    if [[ "$DOMAIN" == *"/"* || "$DOMAIN" == *".."* ]]; then
        die "Nom de domaine potentiellement dangereux refusé : $DOMAIN"
    fi

    if [[ ! "$DOMAIN" =~ ^([A-Za-z0-9_*-]+\.)+[A-Za-z0-9_-]+$ ]]; then
        die "Format de domaine invalide : $DOMAIN"
    fi

    if [[ -n "$ACTION" && "$ACTION" != "--force" ]]; then
        die "Option inconnue : $ACTION"
    fi

    BACKUP="/root/backup_remove_domain_${DOMAIN}_$(date '+%F_%H%M%S')"
}

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        die "Ce script doit être exécuté en tant que root."
    fi
}

check_dependencies() {
    local dependency

    for dependency in nginx systemctl logger grep find cp rm mkdir; do
        if ! command -v "$dependency" >/dev/null 2>&1; then
            die "Commande requise absente : $dependency"
        fi
    done

    if ! command -v certbot >/dev/null 2>&1; then
        log WARNING \
            "Certbot n'est pas installé. La suppression des certificats via Certbot sera ignorée."
    fi
}

###############################################################################
# Recherche des ressources
###############################################################################

find_nginx_matches() {
    local directory
    local file

    NGINX_MATCHES=()

    for directory in "${NGINX_DIRS[@]}"; do
        [[ -d "$directory" ]] || continue

        while IFS= read -r -d '' file; do
            NGINX_MATCHES+=("$file")
        done < <(
            grep \
                --recursive \
                --files-with-matches \
                --null \
                --fixed-strings \
                -- "$DOMAIN" "$directory" 2>/dev/null || true
        )
    done

    if (( ${#NGINX_MATCHES[@]} > 0 )); then
        mapfile -t NGINX_MATCHES < <(
            printf '%s\n' "${NGINX_MATCHES[@]}" | sort -u
        )
    fi
}

find_certbot_certificates() {
    local certificate_name

    CERTBOT_CERTIFICATES=()

    command -v certbot >/dev/null 2>&1 || return 0

    while IFS= read -r certificate_name; do
        [[ -n "$certificate_name" ]] || continue

        if [[ "$certificate_name" == "$DOMAIN" ||
              "$certificate_name" =~ ^${DOMAIN//./\\.}-000[0-9]+$ ]]; then
            CERTBOT_CERTIFICATES+=("$certificate_name")
        fi
    done < <(
        certbot certificates 2>/dev/null \
            | awk '/Certificate Name:/ {print $3}' || true
    )
}

display_detected_resources() {
    local found=0
    local path
    local certificate_name

    log INFO "Début de l'analyse du domaine : $DOMAIN"

    echo
    echo "=== Certbot / Let's Encrypt ==="

    for path in \
        "$LE_DIR/live/$DOMAIN" \
        "$LE_DIR/archive/$DOMAIN" \
        "$LE_DIR/renewal/$DOMAIN.conf"
    do
        if [[ -e "$path" || -L "$path" ]]; then
            echo "✅ Trouvé : $path"
            log INFO "Ressource Let's Encrypt trouvée : $path"
            found=1
        fi
    done

    shopt -s nullglob

    local parasite_paths=(
        "$LE_DIR/live/$DOMAIN"-000*
        "$LE_DIR/archive/$DOMAIN"-000*
        "$LE_DIR/renewal/$DOMAIN"-000*.conf
    )

    shopt -u nullglob

    for path in "${parasite_paths[@]}"; do
        echo "✅ Trouvé parasite : $path"
        log WARNING "Ressource Let's Encrypt parasite trouvée : $path"
        found=1
    done

    for certificate_name in "${CERTBOT_CERTIFICATES[@]}"; do
        log INFO "Certificat Certbot détecté : $certificate_name"
        found=1
    done

    echo
    echo "=== Nginx ==="

    if (( ${#NGINX_MATCHES[@]} > 0 )); then
        for path in "${NGINX_MATCHES[@]}"; do
            echo "✅ Trouvé : $path"
            log INFO "Configuration Nginx trouvée : $path"
        done

        found=1
    else
        echo "Aucune configuration Nginx trouvée."
        log INFO "Aucune configuration Nginx trouvée pour $DOMAIN"
    fi

    if [[ "$found" -ne 1 ]]; then
        log WARNING \
            "Le domaine $DOMAIN ne semble pas être géré sur ce proxy. Aucune suppression effectuée."

        echo
        echo "❌ Le domaine '$DOMAIN' ne semble pas être géré sur ce proxy."
        echo "Aucune suppression effectuée."

        exit 1
    fi
}

###############################################################################
# Sauvegarde
###############################################################################

backup_path() {
    local source_path="$1"
    local destination_directory="$2"
    local destination_name

    [[ -e "$source_path" || -L "$source_path" ]] || return 0

    destination_name="$(
        printf '%s' "$source_path" \
            | sed 's#^/##; s#/#_#g'
    )"

    cp -a -- "$source_path" "$destination_directory/$destination_name"

    log INFO \
        "Sauvegarde effectuée source=$source_path destination=$destination_directory/$destination_name"
}

create_backup() {
    local path
    local backup_nginx_directory="$BACKUP/nginx"
    local backup_letsencrypt_directory="$BACKUP/letsencrypt"

    log INFO "Création de la sauvegarde : $BACKUP"

    mkdir -p \
        "$backup_nginx_directory" \
        "$backup_letsencrypt_directory"

    backup_path "$LE_DIR/live/$DOMAIN" "$backup_letsencrypt_directory"
    backup_path "$LE_DIR/archive/$DOMAIN" "$backup_letsencrypt_directory"
    backup_path "$LE_DIR/renewal/$DOMAIN.conf" "$backup_letsencrypt_directory"

    shopt -s nullglob

    local parasite_paths=(
        "$LE_DIR/live/$DOMAIN"-000*
        "$LE_DIR/archive/$DOMAIN"-000*
        "$LE_DIR/renewal/$DOMAIN"-000*.conf
    )

    shopt -u nullglob

    for path in "${parasite_paths[@]}"; do
        backup_path "$path" "$backup_letsencrypt_directory"
    done

    for path in "${NGINX_MATCHES[@]}"; do
        backup_path "$path" "$backup_nginx_directory"
    done

    {
        echo "Date : $(date --iso-8601=seconds)"
        echo "Serveur : $(hostname -f 2>/dev/null || hostname)"
        echo "Domaine : $DOMAIN"
        echo "Commande : $0 $*"
        echo
        echo "Fichiers Nginx détectés :"

        printf '%s\n' "${NGINX_MATCHES[@]:-Aucun}"

        echo
        echo "Certificats Certbot détectés :"

        printf '%s\n' "${CERTBOT_CERTIFICATES[@]:-Aucun}"
    } > "$BACKUP/manifest.txt"

    log SUCCESS "Sauvegarde terminée : $BACKUP"
}

###############################################################################
# Suppression
###############################################################################

remove_nginx_configuration() {
    local file

    if (( ${#NGINX_MATCHES[@]} == 0 )); then
        log INFO "Aucun fichier Nginx à supprimer pour $DOMAIN"
        return 0
    fi

    for file in "${NGINX_MATCHES[@]}"; do
        if [[ -e "$file" || -L "$file" ]]; then
            log WARNING "Suppression de la configuration Nginx : $file"
            rm -f -- "$file"
        else
            log WARNING \
                "Le fichier Nginx a disparu avant sa suppression : $file"
        fi
    done

    log SUCCESS "Suppression des configurations Nginx terminée"
}

remove_certbot_certificates() {
    local certificate_name

    if ! command -v certbot >/dev/null 2>&1; then
        log WARNING \
            "Certbot indisponible. Nettoyage manuel des fichiers uniquement."
    else
        for certificate_name in "${CERTBOT_CERTIFICATES[@]}"; do
            log WARNING \
                "Suppression du certificat Certbot : $certificate_name"

            if certbot delete \
                --cert-name "$certificate_name" \
                --non-interactive \
                --quiet; then
                log SUCCESS \
                    "Certificat Certbot supprimé : $certificate_name"
            else
                log WARNING \
                    "Échec de certbot delete pour $certificate_name. Nettoyage manuel poursuivi."
            fi
        done
    fi

    log WARNING \
        "Nettoyage manuel des fichiers Let's Encrypt associés à $DOMAIN"

    rm -rf -- \
        "$LE_DIR/live/$DOMAIN" \
        "$LE_DIR/archive/$DOMAIN" \
        "$LE_DIR/renewal/$DOMAIN.conf"

    shopt -s nullglob

    local parasite_paths=(
        "$LE_DIR/live/$DOMAIN"-000*
        "$LE_DIR/archive/$DOMAIN"-000*
        "$LE_DIR/renewal/$DOMAIN"-000*.conf
    )

    if (( ${#parasite_paths[@]} > 0 )); then
        rm -rf -- "${parasite_paths[@]}"
    fi

    shopt -u nullglob

    log SUCCESS "Nettoyage Let's Encrypt terminé pour $DOMAIN"
}

###############################################################################
# Validation Nginx
###############################################################################

validate_and_reload_nginx() {
    log INFO "Exécution du test de configuration Nginx"

    if nginx -t; then
        log SUCCESS "La configuration Nginx est valide"

        if systemctl reload nginx; then
            log SUCCESS "Nginx rechargé avec succès"
        else
            die "La configuration est valide, mais le rechargement de Nginx a échoué."
        fi
    else
        log ERROR "La configuration Nginx est invalide après suppression"
        log ERROR "Sauvegarde disponible dans : $BACKUP"

        echo
        echo "❌ Nginx invalide après suppression."
        echo "Backup disponible : $BACKUP"
        echo "Une restauration manuelle est nécessaire."

        exit 1
    fi
}

###############################################################################
# Programme principal
###############################################################################

main() {
    check_root
    validate_domain
    check_dependencies

    log INFO \
        "Lancement utilisateur=${SUDO_USER:-root} domaine=$DOMAIN mode=${ACTION:-simulation}"

    find_nginx_matches
    find_certbot_certificates
    display_detected_resources

    echo

    if [[ "$ACTION" != "--force" ]]; then
        log INFO \
            "Simulation terminée pour $DOMAIN. Aucune modification effectuée."

        echo "⚠️ Mode simulation uniquement."
        echo "Pour supprimer réellement :"
        echo "$SCRIPT_NAME $DOMAIN --force"

        exit 0
    fi

    log WARNING "Suppression réelle demandée pour le domaine : $DOMAIN"

    echo "🧯 Backup avant suppression : $BACKUP"
    create_backup "$@"

    echo
    echo "🗑️ Suppression Nginx..."
    remove_nginx_configuration

    echo
    echo "🗑️ Suppression Certbot..."
    remove_certbot_certificates

    echo
    echo "🔎 Test Nginx..."
    validate_and_reload_nginx

    echo
    echo "✅ Domaine supprimé proprement : $DOMAIN"
    echo "Backup : $BACKUP"

    log SUCCESS \
        "Domaine supprimé avec succès domaine=$DOMAIN backup=$BACKUP"
}

main "$@"
