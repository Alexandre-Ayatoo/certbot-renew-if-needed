#!/usr/bin/env bash

set -Eeuo pipefail

###############################################################################
# Configuration générale
###############################################################################

readonly SCRIPT_NAME="$(basename "$0")"
readonly LOG_TAG="certbot-renew-if-needed"

readonly RENEW_BEFORE_DAYS=15
readonly REMOTE_USER="root"
readonly ACCOUNT_ID="5f02b9fc3bc5269d443ee5f107fdfc7a"
readonly WEBROOT="/var/www/letsencrypt"

readonly -a PROXIES=(
    "169.0.0.21"
    "169.0.0.22"
    "169.0.0.23"
)

readonly LOCAL_PUBLIC_IPS="$(
    hostname -I 2>/dev/null || true
) 51.75.129.113 51.75.129.105 51.75.129.106 169.0.0.21 169.0.0.22 169.0.0.23"

readonly LOCK="/var/run/certbot-renew-if-needed.lock"
readonly LOG="/var/log/certbot-renew-if-needed.log"

readonly -a SSH_OPTS=(
    -o BatchMode=yes
    -o ConnectTimeout=5
    -o ConnectionAttempts=1
)

TARGET_DOMAIN="${1:-}"
RENEW_ALL=0
FORCE_RENEW=0
LOCAL_PROXY_IP=""

###############################################################################
# Journalisation
###############################################################################

log() {
    local level="$1"
    shift

    local message="$*"
    local syslog_priority="user.info"
    local timestamp

    timestamp="$(date '+%F %T')"

    case "$level" in
        INFO)    syslog_priority="user.info" ;;
        WARNING) syslog_priority="user.warning" ;;
        ERROR)   syslog_priority="user.err" ;;
        SUCCESS) syslog_priority="user.notice" ;;
        DEBUG)   syslog_priority="user.debug" ;;
        *)
            level="INFO"
            syslog_priority="user.info"
            ;;
    esac

    printf '%s [%s] %s\n' "$timestamp" "$level" "$message" | tee -a "$LOG"

    logger \
        --tag "$LOG_TAG" \
        --priority "$syslog_priority" \
        -- "[$level] $message"
}

log_info()    { log INFO "$@"; }
log_warning() { log WARNING "$@"; }
log_error()   { log ERROR "$@"; }
log_success() { log SUCCESS "$@"; }
log_debug()   { log DEBUG "$@"; }

die() {
    log_error "$*"
    exit 1
}

on_error() {
    local exit_code=$?
    local line_number="${BASH_LINENO[0]:-inconnue}"
    local failed_command="${BASH_COMMAND:-inconnue}"

    log_error \
        "Erreur inattendue code=$exit_code ligne=$line_number commande=$failed_command"

    exit "$exit_code"
}

on_exit() {
    local exit_code=$?

    if [[ "$exit_code" -eq 0 ]]; then
        log_debug "Fin normale du script pid=$$"
    else
        log_error "Fin du script avec erreur code=$exit_code pid=$$"
    fi
}

###############################################################################
# Contrôles initiaux
###############################################################################

check_root() {
    if [[ "$EUID" -ne 0 ]]; then
        die "Ce script doit être exécuté en tant que root."
    fi
}

check_dependencies() {
    local dependency
    local dependencies=(
        awk
        certbot
        cut
        date
        dig
        find
        flock
        grep
        hostname
        ip
        logger
        nginx
        openssl
        rsync
        sed
        sort
        ssh
        systemctl
        tail
        tar
        tr
        xargs
    )

    for dependency in "${dependencies[@]}"; do
        if ! command -v "$dependency" >/dev/null 2>&1; then
            die "Commande requise absente : $dependency"
        fi
    done
}

prepare_environment() {
    mkdir -p "$WEBROOT/.well-known/acme-challenge"

    touch "$LOG"
    chmod 640 "$LOG"

    log_debug "Répertoire ACME vérifié : $WEBROOT/.well-known/acme-challenge"
    log_debug "Fichier de log vérifié : $LOG"
}

acquire_lock() {
    exec 9>"$LOCK"

    if ! flock -n 9; then
        log_warning \
            "Une autre instance du script est déjà en cours. Verrou=$LOCK"
        exit 1
    fi

    log_debug "Verrou acquis : $LOCK"
}

parse_arguments() {
    case "$TARGET_DOMAIN" in
        all)
            RENEW_ALL=1
            ;;
        --force)
            TARGET_DOMAIN=""
            FORCE_RENEW=1
            ;;
        "")
            ;;
    esac

    if [[ "${2:-}" == "--force" ]]; then
        FORCE_RENEW=1
    elif [[ -n "${2:-}" ]]; then
        die "Option inconnue : ${2:-}"
    fi

    if [[ "$TARGET_DOMAIN" == "all" ]]; then
        RENEW_ALL=1
    fi

    log_info \
        "Lancement utilisateur=${SUDO_USER:-root} argument=${TARGET_DOMAIN:-sélection-interactive} force=$FORCE_RENEW pid=$$"
}

###############################################################################
# Fonctions réseau
###############################################################################

local_ip() {
    local proxy_ip

    for proxy_ip in "${PROXIES[@]}"; do
        if ip -4 -o addr show \
            | awk '{print $4}' \
            | cut -d/ -f1 \
            | grep -Fxq -- "$proxy_ip"; then

            printf '%s\n' "$proxy_ip"
            return 0
        fi
    done

    return 1
}

get_peers() {
    local proxy_ip

    for proxy_ip in "${PROXIES[@]}"; do
        [[ "$proxy_ip" == "$LOCAL_PROXY_IP" ]] && continue
        printf '%s\n' "$proxy_ip"
    done
}

is_cluster_proxy() {
    local searched_ip="$1"
    local proxy_ip

    for proxy_ip in "${PROXIES[@]}"; do
        if [[ "$searched_ip" == "$proxy_ip" ]]; then
            return 0
        fi
    done

    grep -qw -- "$searched_ip" <<< "$LOCAL_PUBLIC_IPS"
}

###############################################################################
# Fonctions certificats
###############################################################################

cert_end_epoch() {
    local certificate="$1"
    local end_date

    [[ -f "$certificate" ]] || return 1

    end_date="$(
        openssl x509 \
            -enddate \
            -noout \
            -in "$certificate" 2>/dev/null \
            | cut -d= -f2-
    )"

    [[ -n "$end_date" ]] || return 1

    date --date="$end_date" +%s 2>/dev/null
}

cert_days_left() {
    local certificate="$1"
    local expiry
    local now

    expiry="$(cert_end_epoch "$certificate" || printf '0')"
    now="$(date +%s)"

    if [[ ! "$expiry" =~ ^[0-9]+$ ]]; then
        expiry=0
    fi

    printf '%s\n' "$(( (expiry - now) / 86400 ))"
}

cert_fingerprint() {
    local certificate="$1"

    [[ -f "$certificate" ]] || return 1

    openssl x509 \
        -in "$certificate" \
        -noout \
        -fingerprint \
        -sha256 2>/dev/null \
        | cut -d= -f2- \
        | tr -d ':'
}

validate_local_certificate() {
    local domain="$1"
    local certificate="/etc/letsencrypt/live/$domain/fullchain.pem"

    if [[ ! -f "$certificate" ]]; then
        log_error "[$domain] Certificat local absent : $certificate"
        return 1
    fi

    if ! openssl x509 -in "$certificate" -noout >/dev/null 2>&1; then
        log_error "[$domain] Certificat local illisible ou invalide"
        return 1
    fi

    if ! openssl x509 -in "$certificate" -noout -checkend 0 >/dev/null 2>&1; then
        log_error "[$domain] Certificat local expiré ou déjà invalide"
        return 1
    fi

    if ! openssl x509 -in "$certificate" -noout -checkhost "$domain" >/dev/null 2>&1; then
        log_error "[$domain] Le certificat local ne couvre pas le nom de domaine"
        return 1
    fi

    log_success "[$domain] Certificat local validé avant distribution"
    return 0
}

###############################################################################
# DNS
###############################################################################

get_dns_ips() {
    local domain="$1"

    dig @213.186.33.99 +short A "$domain" 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -u
}

dns_points_to_cluster() {
    local domain="$1"
    local dns_ips
    local dns_ip

    dns_ips="$(get_dns_ips "$domain")"

    if [[ -z "$dns_ips" ]]; then
        log_warning "[$domain] Aucune adresse IPv4 trouvée dans le DNS"
        return 1
    fi

    log_info \
        "[$domain] Adresse(s) IPv4 détectée(s) dans le DNS : $(echo "$dns_ips" | tr '\n' ' ')"

    for dns_ip in $dns_ips; do
        if grep -qw -- "$dns_ip" <<< "$LOCAL_PUBLIC_IPS"; then
            log_success \
                "[$domain] Le DNS pointe vers une adresse connue du cluster : $dns_ip"
            return 0
        fi
    done

    log_warning \
        "[$domain] Le DNS ne pointe pas vers le cluster proxy connu : $(echo "$dns_ips" | tr '\n' ' ')"

    return 1
}

###############################################################################
# Détection des hôtes de synchronisation
#
# Syntaxes prises en charge :
#
#   proxy_pass http://169.0.0.11;
#   proxy_pass https://169.0.0.11;
#   server 169.0.0.11:443;
#
# Synchronisation explicite même si aucun proxy_pass n'est actif :
#
#   # certbot-sync 169.0.0.11
#
# Une ancienne ligne commentée du type :
#
#   # proxy_pass http://169.0.0.11;
#
# n'est PAS considérée comme une cible.
###############################################################################

get_nginx_files_for_domain() {
    local domain="$1"
    local path

    for path in \
        "/etc/nginx/sites-enabled/$domain" \
        "/etc/nginx/sites-available/$domain"; do
        [[ -f "$path" ]] && printf '%s\n' "$path"
    done

    shopt -s nullglob
    for path in /etc/nginx/conf.d/*.conf; do
        [[ -f "$path" ]] && printf '%s\n' "$path"
    done
    shopt -u nullglob
}

get_backend_ips_from_nginx() {
    local domain="$1"
    local file

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue

        # upstream actif : server 169.0.0.11:443;
        grep -hoP \
            '^\s*(?!#).*?\bserver\s+\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?=:[0-9]+)' \
            "$file" 2>/dev/null || true

        # proxy_pass actif : proxy_pass http(s)://169.0.0.11;
        grep -hoP \
            '^\s*(?!#).*?\bproxy_pass\s+https?://\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?=[:/;])' \
            "$file" 2>/dev/null || true

    done < <(get_nginx_files_for_domain "$domain") \
        | sort -u
}

get_forced_sync_ips() {
    local domain="$1"
    local file

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue

        grep -hoP \
            '^\s*#\s*certbot-sync\s+\K[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' \
            "$file" 2>/dev/null || true

    done < <(get_nginx_files_for_domain "$domain") \
        | sort -u
}

###############################################################################
# Validation et rechargement Nginx local
###############################################################################

test_and_reload_nginx() {
    local context="$1"
    local nginx_output

    log_info "Test de la configuration Nginx contexte=$context"

    if ! nginx_output="$(nginx -t 2>&1)"; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && log_error "Nginx : $line"
        done <<< "$nginx_output"

        return 1
    fi

    while IFS= read -r line; do
        [[ -n "$line" ]] && log_info "Nginx : $line"
    done <<< "$nginx_output"

    if ! systemctl reload nginx; then
        log_error "Échec du rechargement de Nginx contexte=$context"
        return 1
    fi

    log_success "Nginx rechargé avec succès contexte=$context"
}

###############################################################################
# Normalisation des certificats parasites -000X
###############################################################################

normalize_cert_name() {
    local domain="$1"
    local canonical="/etc/letsencrypt/live/$domain/fullchain.pem"
    local canonical_exp=0
    local alt
    local best_alt=""
    local best_alt_exp=0
    local exp
    local backup
    local backup_path
    local archive_dir
    local last_num

    canonical_exp="$(cert_end_epoch "$canonical" || printf '0')"
    [[ "$canonical_exp" =~ ^[0-9]+$ ]] || canonical_exp=0

    shopt -s nullglob

    for alt in "/etc/letsencrypt/live/$domain"-000*; do
        [[ -d "$alt" ]] || continue

        exp="$(cert_end_epoch "$alt/fullchain.pem" || printf '0')"
        [[ "$exp" =~ ^[0-9]+$ ]] || exp=0

        log_debug \
            "[$domain] Certificat alternatif détecté nom=$(basename "$alt") expiration_epoch=$exp"

        if (( exp > best_alt_exp )); then
            best_alt_exp="$exp"
            best_alt="$(basename "$alt")"
        fi
    done

    shopt -u nullglob

    [[ -n "$best_alt" ]] || return 0

    if (( canonical_exp >= best_alt_exp && canonical_exp > 0 )); then
        log_warning \
            "[$domain] Certificat parasite $best_alt détecté mais le certificat canonique est aussi récent ou plus récent ; aucune promotion effectuée"
        return 0
    fi

    log_warning \
        "[$domain] Certificat alternatif plus récent détecté : $best_alt. Normalisation vers $domain"

    backup="/root/backup_certbot_normalize_${domain}_$(date '+%F_%H%M%S')"
    mkdir -p "$backup"

    log_info "[$domain] Création du backup de normalisation : $backup"

    shopt -s nullglob

    for backup_path in \
        /etc/letsencrypt/live/"$domain"* \
        /etc/letsencrypt/archive/"$domain"* \
        /etc/letsencrypt/renewal/"$domain"*; do

        [[ -e "$backup_path" || -L "$backup_path" ]] || continue
        cp -a -- "$backup_path" "$backup/"
    done

    shopt -u nullglob

    rm -rf -- "/etc/letsencrypt/live/$domain"
    rm -rf -- "/etc/letsencrypt/archive/$domain"
    rm -f -- "/etc/letsencrypt/renewal/$domain.conf"

    mv \
        "/etc/letsencrypt/live/$best_alt" \
        "/etc/letsencrypt/live/$domain"

    if [[ -d "/etc/letsencrypt/archive/$best_alt" ]]; then
        mv \
            "/etc/letsencrypt/archive/$best_alt" \
            "/etc/letsencrypt/archive/$domain"
    fi

    if [[ -f "/etc/letsencrypt/renewal/$best_alt.conf" ]]; then
        mv \
            "/etc/letsencrypt/renewal/$best_alt.conf" \
            "/etc/letsencrypt/renewal/$domain.conf"
    fi

    archive_dir="/etc/letsencrypt/archive/$domain"

    last_num="$(
        find "$archive_dir" \
            -maxdepth 1 \
            -type f \
            -name 'fullchain*.pem' \
            -printf '%f\n' 2>/dev/null \
            | sed -E 's/^fullchain([0-9]+)\.pem$/\1/' \
            | sort -n \
            | tail -n1
    )"

    if [[ -z "$last_num" ]]; then
        log_error \
            "[$domain] Impossible de déterminer la dernière version dans $archive_dir"
        return 1
    fi

    rm -f \
        "/etc/letsencrypt/live/$domain/cert.pem" \
        "/etc/letsencrypt/live/$domain/chain.pem" \
        "/etc/letsencrypt/live/$domain/fullchain.pem" \
        "/etc/letsencrypt/live/$domain/privkey.pem"

    ln -s "../../archive/$domain/cert${last_num}.pem" \
        "/etc/letsencrypt/live/$domain/cert.pem"

    ln -s "../../archive/$domain/chain${last_num}.pem" \
        "/etc/letsencrypt/live/$domain/chain.pem"

    ln -s "../../archive/$domain/fullchain${last_num}.pem" \
        "/etc/letsencrypt/live/$domain/fullchain.pem"

    ln -s "../../archive/$domain/privkey${last_num}.pem" \
        "/etc/letsencrypt/live/$domain/privkey.pem"

    log_info \
        "[$domain] Liens symboliques reconstruits avec la version $last_num"

    if [[ -f "/etc/letsencrypt/renewal/$domain.conf" ]]; then
        sed -i \
            "s#$best_alt#$domain#g" \
            "/etc/letsencrypt/renewal/$domain.conf"
    fi

    sed -i \
        "s#$best_alt#$domain#g" \
        /etc/nginx/sites-enabled/* \
        /etc/nginx/sites-available/* \
        /etc/nginx/conf.d/*.conf 2>/dev/null || true

    if ! test_and_reload_nginx "normalisation-$domain"; then
        log_error \
            "[$domain] Nginx invalide après normalisation backup=$backup"
        return 1
    fi

    log_success \
        "[$domain] Certificat normalisé proprement backup=$backup"

    return 0
}

###############################################################################
# Informations certificat d'un hôte distant
###############################################################################

get_host_certificate_info() {
    local domain="$1"
    local host="$2"

    ssh \
        -n \
        "${SSH_OPTS[@]}" \
        "$REMOTE_USER@$host" \
        "
            certificate='/etc/letsencrypt/live/$domain/fullchain.pem'

            if ! command -v openssl >/dev/null 2>&1; then
                printf 'NO_OPENSSL|0\\n'
                exit 2
            fi

            if [ ! -f \"\$certificate\" ]; then
                printf 'MISSING|0\\n'
                exit 0
            fi

            fingerprint=\$(
                openssl x509 \
                    -in \"\$certificate\" \
                    -noout \
                    -fingerprint \
                    -sha256 2>/dev/null \
                | cut -d= -f2- \
                | tr -d ':'
            )

            expiry=\$(
                openssl x509 \
                    -in \"\$certificate\" \
                    -noout \
                    -enddate 2>/dev/null \
                | cut -d= -f2- \
                | xargs -r -I{} date --date='{}' +%s 2>/dev/null
            )

            printf '%s|%s\\n' \"\${fingerprint:-INVALID}\" \"\${expiry:-0}\"
        " 2>/dev/null
}

###############################################################################
# Copie d'un certificat vers un hôte
#
# Nginx n'est PAS obligatoire sur l'hôte distant.
# Si Nginx est installé et actif, nginx -t puis reload.
# Sinon, le certificat est simplement copié et vérifié.
###############################################################################

copy_cert_to_host() {
    local domain="$1"
    local host="$2"
    local ssh_target="${REMOTE_USER}@${host}"
    local remote_output

    log_info \
        "[$domain] Préparation de l'envoi du certificat vers $host"

    if ! remote_output="$(
        ssh \
            -n \
            "${SSH_OPTS[@]}" \
            -- "$ssh_target" \
            "
                set -e

                command -v tar >/dev/null

                mkdir -p \
                    '/etc/letsencrypt/live' \
                    '/etc/letsencrypt/archive' \
                    '/etc/letsencrypt/renewal'
            " 2>&1
    )"; then
        log_error \
            "[$domain] Préparation distante impossible sur $host : ${remote_output:-aucun détail}"
        return 1
    fi

    log_debug \
        "[$domain] Connexion SSH et environnement validés vers $host"

    # On copie archive AVANT live pour éviter des liens symboliques live cassés
    # pendant le transfert.
    log_info \
        "[$domain] Envoi du répertoire archive vers $host"

    if ! tar \
        -C /etc/letsencrypt/archive \
        -cpf - \
        "$domain" \
        | ssh \
            "${SSH_OPTS[@]}" \
            -- "$ssh_target" \
            "
                set -e

                rm -rf '/etc/letsencrypt/archive/$domain'
                mkdir -p /etc/letsencrypt/archive

                tar \
                    -C /etc/letsencrypt/archive \
                    -xpf -
            "; then

        log_error \
            "[$domain] Échec du transfert du répertoire archive vers $host"
        return 1
    fi

    log_info \
        "[$domain] Envoi du répertoire live vers $host"

    if ! tar \
        -C /etc/letsencrypt/live \
        -cpf - \
        "$domain" \
        | ssh \
            "${SSH_OPTS[@]}" \
            -- "$ssh_target" \
            "
                set -e

                rm -rf '/etc/letsencrypt/live/$domain'
                mkdir -p /etc/letsencrypt/live

                tar \
                    -C /etc/letsencrypt/live \
                    -xpf -
            "; then

        log_error \
            "[$domain] Échec du transfert du répertoire live vers $host"
        return 1
    fi

    if [[ -f "/etc/letsencrypt/renewal/$domain.conf" ]]; then
        log_info \
            "[$domain] Envoi de la configuration renewal vers $host"

        if ! ssh \
            "${SSH_OPTS[@]}" \
            -- "$ssh_target" \
            "cat > '/etc/letsencrypt/renewal/$domain.conf'" \
            < "/etc/letsencrypt/renewal/$domain.conf"; then

            log_error \
                "[$domain] Échec du transfert de la configuration renewal vers $host"
            return 1
        fi
    else
        log_debug \
            "[$domain] Aucun fichier renewal local à envoyer"
    fi

    if ! remote_output="$(
        ssh \
            -n \
            "${SSH_OPTS[@]}" \
            -- "$ssh_target" \
            "
                set -e

                nginx_active=0

                if command -v nginx >/dev/null 2>&1; then
                    if command -v systemctl >/dev/null 2>&1; then
                        if systemctl is-active --quiet nginx; then
                            nginx_active=1
                        fi
                    elif command -v service >/dev/null 2>&1; then
                        if service nginx status >/dev/null 2>&1; then
                            nginx_active=1
                        fi
                    fi
                fi

                if [ \"\$nginx_active\" -eq 1 ]; then

                    sed -i \
                        's#$domain-000[0-9]*#$domain#g' \
                        /etc/nginx/sites-enabled/* \
                        /etc/nginx/sites-available/* \
                        /etc/nginx/conf.d/*.conf \
                        2>/dev/null || true

                    nginx -t

                    if command -v systemctl >/dev/null 2>&1; then
                        systemctl reload nginx
                    else
                        nginx -s reload
                    fi

                    printf 'CERTBOT_REMOTE_STATUS=NGINX_RELOADED\\n'
                else
                    printf 'CERTBOT_REMOTE_STATUS=NGINX_ABSENT_OR_INACTIVE\\n'
                fi
            " 2>&1
    )"; then
        while IFS= read -r line; do
            [[ -n "$line" ]] \
                && log_error "[$domain] Hôte distant $host : $line"
        done <<< "$remote_output"

        log_error \
            "[$domain] Certificat copié, mais le traitement post-copie a échoué sur $host"
        return 1
    fi

    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        [[ "$line" == CERTBOT_REMOTE_STATUS=* ]] && continue
        log_info "[$domain] Hôte distant $host : $line"
    done <<< "$remote_output"

    if grep -q '^CERTBOT_REMOTE_STATUS=NGINX_RELOADED$' <<< "$remote_output"; then
        log_success \
            "[$domain] Certificat envoyé et Nginx rechargé sur $host"
    else
        log_success \
            "[$domain] Certificat envoyé sur $host - Nginx absent ou inactif, aucun rechargement"
    fi

    return 0
}

###############################################################################
# Synchronisation conditionnelle vers un hôte
###############################################################################

sync_cert_to_host_if_needed() {
    local domain="$1"
    local host="$2"
    local role="${3:-hôte}"
    local local_cert="/etc/letsencrypt/live/$domain/fullchain.pem"
    local local_fingerprint
    local remote_info
    local remote_fingerprint
    local remote_expiry
    local verified_info
    local verified_fingerprint

    local_fingerprint="$(cert_fingerprint "$local_cert" || true)"

    if [[ -z "$local_fingerprint" ]]; then
        log_error \
            "[$domain] Empreinte locale indisponible, synchronisation vers $host annulée"
        return 1
    fi

    if remote_info="$(get_host_certificate_info "$domain" "$host")"; then
        remote_fingerprint="${remote_info%%|*}"
        remote_expiry="${remote_info#*|}"

        if [[ "$remote_fingerprint" == "$local_fingerprint" ]]; then
            log_success \
                "[$domain] Certificat déjà à jour sur $role $host expiration_epoch=$remote_expiry"
            return 0
        fi

        log_warning \
            "[$domain] Certificat absent ou différent sur $role $host, mise à jour nécessaire"
    else
        log_warning \
            "[$domain] Vérification initiale impossible sur $role $host, tentative de synchronisation"
    fi

    if ! copy_cert_to_host "$domain" "$host"; then
        log_error \
            "[$domain] Échec de copie du certificat vers $role $host"
        return 1
    fi

    if ! verified_info="$(get_host_certificate_info "$domain" "$host")"; then
        log_error \
            "[$domain] Copie effectuée mais vérification finale impossible sur $role $host. Vérifie notamment la présence d'openssl."
        return 1
    fi

    verified_fingerprint="${verified_info%%|*}"

    if [[ "$verified_fingerprint" != "$local_fingerprint" ]]; then
        log_error \
            "[$domain] Empreinte incorrecte après synchronisation sur $role $host"
        return 1
    fi

    log_success \
        "[$domain] Certificat vérifié après synchronisation sur $role $host"

    return 0
}

###############################################################################
# Récupération d'un certificat plus récent depuis un proxy pair
###############################################################################

pull_cert_from_peer_if_newer() {
    local domain="$1"
    local local_cert="/etc/letsencrypt/live/$domain/fullchain.pem"
    local local_expiry
    local best_peer=""
    local best_expiry
    local peer
    local peer_expiry
    local -a peers=()

    local_expiry="$(cert_end_epoch "$local_cert" || printf '0')"
    [[ "$local_expiry" =~ ^[0-9]+$ ]] || local_expiry=0

    best_expiry="$local_expiry"

    log_debug \
        "[$domain] Expiration locale epoch=$local_expiry"

    mapfile -t peers < <(get_peers)

    if (( ${#peers[@]} > 0 )); then
        log_debug \
            "[$domain] Proxies distants recherchés : ${peers[*]}"
    else
        log_warning \
            "[$domain] Aucun proxy distant configuré"
    fi

    for peer in "${peers[@]}"; do
        [[ -n "$peer" ]] || continue

        if ! peer_expiry="$(
            ssh \
                -n \
                "${SSH_OPTS[@]}" \
                "$REMOTE_USER@$peer" \
                "
                    certificate='/etc/letsencrypt/live/$domain/fullchain.pem'

                    if [ ! -f \"\$certificate\" ]; then
                        printf '0\\n'
                        exit 0
                    fi

                    openssl x509 \
                        -enddate \
                        -noout \
                        -in \"\$certificate\" 2>/dev/null \
                    | cut -d= -f2- \
                    | xargs -r -I{} date --date='{}' +%s 2>/dev/null
                " 2>/dev/null
        )"; then
            peer_expiry=0
            log_warning \
                "[$domain] Vérification impossible sur le proxy $peer"
        fi

        [[ "$peer_expiry" =~ ^[0-9]+$ ]] || peer_expiry=0

        log_debug \
            "[$domain] Proxy=$peer expiration_epoch=$peer_expiry"

        if (( peer_expiry > best_expiry )); then
            best_expiry="$peer_expiry"
            best_peer="$peer"
        fi
    done

    if [[ -z "$best_peer" ]]; then
        log_info \
            "[$domain] Aucun certificat plus récent trouvé sur les autres proxies"
        return 1
    fi

    log_info \
        "[$domain] Certificat plus récent trouvé sur $best_peer expiration_epoch=$best_expiry"

    mkdir -p \
        "/etc/letsencrypt/live/$domain" \
        "/etc/letsencrypt/archive/$domain" \
        /etc/letsencrypt/renewal

    # Archive d'abord, live ensuite pour conserver des symlinks cohérents.
    if ! rsync \
        -az \
        --delete \
        -e "ssh -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1" \
        -- \
        "$REMOTE_USER@$best_peer:/etc/letsencrypt/archive/$domain/" \
        "/etc/letsencrypt/archive/$domain/"; then

        log_error \
            "[$domain] Échec de récupération du répertoire archive depuis $best_peer"
        return 1
    fi

    if ! rsync \
        -az \
        --delete \
        -e "ssh -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1" \
        -- \
        "$REMOTE_USER@$best_peer:/etc/letsencrypt/live/$domain/" \
        "/etc/letsencrypt/live/$domain/"; then

        log_error \
            "[$domain] Échec de récupération du répertoire live depuis $best_peer"
        return 1
    fi

    rsync \
        -az \
        -e "ssh -o BatchMode=yes -o ConnectTimeout=5 -o ConnectionAttempts=1" \
        -- \
        "$REMOTE_USER@$best_peer:/etc/letsencrypt/renewal/$domain.conf" \
        "/etc/letsencrypt/renewal/$domain.conf" 2>/dev/null || {
            log_warning \
                "[$domain] Fichier renewal non récupéré depuis $best_peer"
        }

    if ! validate_local_certificate "$domain"; then
        log_error \
            "[$domain] Certificat récupéré depuis $best_peer mais validation locale échouée"
        return 1
    fi

    if ! test_and_reload_nginx "récupération-$domain-depuis-$best_peer"; then
        log_error \
            "[$domain] Certificat récupéré depuis $best_peer, mais Nginx est invalide"
        return 1
    fi

    log_success \
        "[$domain] Certificat récupéré depuis $best_peer"

    return 0
}

###############################################################################
# Vérification des backends et cibles explicites
###############################################################################

verify_remote_targets() {
    local domain="$1"
    local ip
    local failures=0
    local checked=0
    local conformes=0
    local -A seen=()

    if ! validate_local_certificate "$domain"; then
        return 1
    fi

    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        is_cluster_proxy "$ip" && continue
        [[ -n "${seen[$ip]:-}" ]] && continue
        seen["$ip"]=1

        ((checked += 1))

        if sync_cert_to_host_if_needed "$domain" "$ip" "backend"; then
            ((conformes += 1))
        else
            ((failures += 1))
        fi
    done < <(get_backend_ips_from_nginx "$domain")

    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue
        is_cluster_proxy "$ip" && continue
        [[ -n "${seen[$ip]:-}" ]] && continue
        seen["$ip"]=1

        ((checked += 1))

        if sync_cert_to_host_if_needed "$domain" "$ip" "certbot-sync"; then
            ((conformes += 1))
        else
            ((failures += 1))
        fi
    done < <(get_forced_sync_ips "$domain")

    if (( checked == 0 )); then
        log_info \
            "[$domain] Aucun backend ni cible certbot-sync supplémentaire à vérifier"
        return 0
    fi

    log_info \
        "[$domain] Vérification des cibles terminée équipements=$checked conformes=$conformes erreurs=$failures"

    (( failures == 0 ))
}

###############################################################################
# Distribution vers l'ensemble du cluster et des cibles
###############################################################################

push_cert_everywhere() {
    local domain="$1"
    local peer
    local ip
    local failures=0
    local -a peers=()
    local -A seen=()

    if ! validate_local_certificate "$domain"; then
        log_error \
            "[$domain] Distribution annulée : certificat local non validé"
        return 1
    fi

    log_info \
        "[$domain] Début de la vérification et de la distribution du certificat"

    mapfile -t peers < <(get_peers)

    if (( ${#peers[@]} > 0 )); then
        log_info \
            "[$domain] Proxies distants à contrôler : ${peers[*]}"
    else
        log_warning \
            "[$domain] Aucun proxy distant détecté"
    fi

    for peer in "${peers[@]}"; do
        [[ -n "$peer" ]] || continue
        seen["$peer"]=1

        log_info \
            "[$domain] Contrôle du certificat sur le proxy $peer"

        if ! sync_cert_to_host_if_needed "$domain" "$peer" "proxy"; then
            ((failures += 1))
        fi
    done

    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue

        if is_cluster_proxy "$ip"; then
            log_debug \
                "[$domain] Backend ignoré car membre du cluster : $ip"
            continue
        fi

        [[ -n "${seen[$ip]:-}" ]] && continue
        seen["$ip"]=1

        log_info \
            "[$domain] Contrôle du certificat sur le backend $ip"

        if ! sync_cert_to_host_if_needed "$domain" "$ip" "backend"; then
            ((failures += 1))
        fi
    done < <(get_backend_ips_from_nginx "$domain")

    while IFS= read -r ip; do
        [[ -n "$ip" ]] || continue

        if is_cluster_proxy "$ip"; then
            log_debug \
                "[$domain] Cible certbot-sync ignorée car membre du cluster : $ip"
            continue
        fi

        [[ -n "${seen[$ip]:-}" ]] && continue
        seen["$ip"]=1

        log_info \
            "[$domain] Contrôle du certificat sur la cible certbot-sync $ip"

        if ! sync_cert_to_host_if_needed "$domain" "$ip" "certbot-sync"; then
            ((failures += 1))
        fi
    done < <(get_forced_sync_ips "$domain")

    if (( failures > 0 )); then
        log_error \
            "[$domain] Distribution terminée avec $failures erreur(s)"
        return 1
    fi

    log_success \
        "[$domain] Tous les proxies, backends et cibles certbot-sync présentent le certificat validé"

    return 0
}

###############################################################################
# Renouvellement Certbot
###############################################################################

renew_local_cert() {
    local domain="$1"
    local certbot_output
    local -a certbot_args

    # Conserver les hooks HTTP distribués et les SAN des nouveaux domaines.
    if grep -Eq '^authenticator[[:space:]]*=[[:space:]]*manual[[:space:]]*$' \
        "/etc/letsencrypt/renewal/$domain.conf" 2>/dev/null; then
        certbot_args=(renew --cert-name "$domain" --non-interactive)
    else
        certbot_args=(certonly --webroot --webroot-path "$WEBROOT"
            --domain "$domain" --cert-name "$domain" --account "$ACCOUNT_ID"
            --non-interactive --agree-tos)
    fi

    log_info \
        "[$domain] Début du renouvellement local"

    if ! certbot_output="$(
        certbot "${certbot_args[@]}" 2>&1
    )"; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && log_error "[$domain] Certbot : $line"
        done <<< "$certbot_output"

        log_error \
            "[$domain] Échec du renouvellement local"
        return 1
    fi

    while IFS= read -r line; do
        [[ -n "$line" ]] && log_info "[$domain] Certbot : $line"
    done <<< "$certbot_output"

    if ! normalize_cert_name "$domain"; then
        log_error \
            "[$domain] Échec de la normalisation après renouvellement"
        return 1
    fi

    if ! validate_local_certificate "$domain"; then
        log_error \
            "[$domain] Certificat invalide après renouvellement"
        return 1
    fi

    # Reload effectué ici, une seule fois, après validation.
    if ! test_and_reload_nginx "renouvellement-local-$domain"; then
        log_error \
            "[$domain] Nginx invalide après le renouvellement local"
        return 1
    fi

    log_success \
        "[$domain] Certificat renouvelé localement"

    return 0
}

###############################################################################
# Sélection d'un domaine
###############################################################################

select_domain() {
    local domains=()
    local cert_dir
    local domain
    local index
    local choice

    shopt -s nullglob

    for cert_dir in /etc/letsencrypt/live/*; do
        [[ -d "$cert_dir" ]] || continue

        domain="$(basename "$cert_dir")"

        [[ "$domain" == *-000* ]] && continue
        [[ -f "$cert_dir/fullchain.pem" ]] || continue

        domains+=("$domain")
    done

    shopt -u nullglob

    if (( ${#domains[@]} == 0 )); then
        die "Aucun certificat trouvé dans /etc/letsencrypt/live/"
    fi

    echo "Domaines disponibles :"
    echo

    for index in "${!domains[@]}"; do
        echo "$((index + 1))) ${domains[$index]}"
    done

    echo
    read -rp "Sélectionne le numéro du domaine à traiter : " choice

    if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
        die "Choix invalide : $choice"
    fi

    if (( choice < 1 || choice > ${#domains[@]} )); then
        die "Choix hors limites : $choice"
    fi

    TARGET_DOMAIN="${domains[$((choice - 1))]}"

    log_info \
        "Domaine sélectionné manuellement : $TARGET_DOMAIN"
}

###############################################################################
# Traitement d'un domaine
###############################################################################

process_domain() {
    local domain="$1"
    local cert_path="/etc/letsencrypt/live/$domain/fullchain.pem"
    local days_left

    log_info \
        "[$domain] Début du traitement"

    if [[ ! -f "$cert_path" ]]; then
        log_error \
            "[$domain] Certificat introuvable : $cert_path"
        return 1
    fi

    if ! normalize_cert_name "$domain"; then
        log_error \
            "[$domain] Échec de la normalisation du certificat"
        return 1
    fi

    if ! validate_local_certificate "$domain"; then
        return 1
    fi

    days_left="$(cert_days_left "$cert_path")"

    log_info \
        "[$domain] Validité restante : $days_left jour(s), seuil=$RENEW_BEFORE_DAYS jour(s), force=$FORCE_RENEW"

    # Certificat encore suffisamment valide :
    # on cherche d'abord une éventuelle version plus récente sur un pair,
    # puis on synchronise tout le monde.
    if (( FORCE_RENEW == 0 && days_left > RENEW_BEFORE_DAYS )); then
        log_success \
            "[$domain] Certificat encore valide, renouvellement non nécessaire"

        if pull_cert_from_peer_if_newer "$domain"; then
            log_info \
                "[$domain] Un certificat plus récent a été récupéré depuis un pair"
        fi

        if ! push_cert_everywhere "$domain"; then
            log_error \
                "[$domain] Au moins une cible n'a pas pu être vérifiée ou resynchronisée"
            return 1
        fi

        log_success \
            "[$domain] Traitement terminé sans renouvellement"

        return 0
    fi

    log_warning \
        "[$domain] Renouvellement nécessaire ou forcé"

    # Avant de contacter Let's Encrypt, vérifier si un autre proxy possède déjà
    # un certificat plus récent.
    if pull_cert_from_peer_if_newer "$domain"; then
        log_info \
            "[$domain] Utilisation du certificat plus récent récupéré depuis le cluster"

        if ! push_cert_everywhere "$domain"; then
            log_error \
                "[$domain] Échec de distribution après récupération depuis un pair"
            return 1
        fi

        log_success \
            "[$domain] Traitement terminé avec synchronisation depuis un pair"

        return 0
    fi

    # On ne tente un challenge HTTP-01 que si le DNS pointe vers le cluster.
    if ! dns_points_to_cluster "$domain"; then
        log_warning \
            "[$domain] Renouvellement ignoré car le DNS ne pointe pas vers le cluster"

        if ! verify_remote_targets "$domain"; then
            log_warning \
                "[$domain] Au moins une cible distante n'a pas pu être vérifiée ou resynchronisée"
        fi

        return 1
    fi

    if ! renew_local_cert "$domain"; then
        log_error \
            "[$domain] Le renouvellement local a échoué"

        if ! verify_remote_targets "$domain"; then
            log_warning \
                "[$domain] Au moins une cible distante n'a pas pu être vérifiée"
        fi

        return 1
    fi

    if ! push_cert_everywhere "$domain"; then
        log_error \
            "[$domain] Certificat renouvelé localement mais distribution incomplète"
        return 1
    fi

    log_success \
        "[$domain] Traitement terminé avec renouvellement local"

    return 0
}

###############################################################################
# Traitement global
###############################################################################

process_all_domains() {
    local cert_dir
    local domain
    local total=0
    local successes=0
    local failures=0

    log_info \
        "Mode renouvellement global activé"

    shopt -s nullglob

    for cert_dir in /etc/letsencrypt/live/*; do
        [[ -d "$cert_dir" ]] || continue

        domain="$(basename "$cert_dir")"

        [[ "$domain" == *-000* ]] && continue
        [[ -f "$cert_dir/fullchain.pem" ]] || continue

        ((total += 1))

        log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_info "[$domain] Traitement global"

        if process_domain "$domain"; then
            ((successes += 1))
        else
            ((failures += 1))
            log_warning \
                "[$domain] Traitement global terminé avec erreur"
        fi
    done

    shopt -u nullglob

    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info \
        "Fin du renouvellement global total=$total succès=$successes erreurs=$failures"

    if (( failures > 0 )); then
        return 1
    fi

    return 0
}

###############################################################################
# Programme principal
###############################################################################

main() {
    trap on_error ERR
    trap on_exit EXIT
    check_root
    prepare_environment
    acquire_lock
    check_dependencies
    parse_arguments "$@"

    LOCAL_PROXY_IP="$(local_ip || true)"

    if [[ -n "$LOCAL_PROXY_IP" ]]; then
        log_info \
            "Proxy local identifié : $LOCAL_PROXY_IP"
    else
        log_warning \
            "Impossible d'identifier l'adresse privée du proxy local parmi : ${PROXIES[*]}"
    fi

    if (( RENEW_ALL == 1 )); then
        if process_all_domains; then
            log_success \
                "Fin du traitement global"
            return 0
        fi

        log_error \
            "Fin du traitement global avec erreur"
        return 1
    fi

    if [[ -z "$TARGET_DOMAIN" ]]; then
        select_domain
    fi

    if process_domain "$TARGET_DOMAIN"; then
        log_success \
            "Fin du traitement pour $TARGET_DOMAIN"
    else
        log_error \
            "Traitement terminé avec erreur pour $TARGET_DOMAIN"
        return 1
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
