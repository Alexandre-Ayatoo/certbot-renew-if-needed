#!/usr/bin/env bash
# Création d'un site Nginx et de son certificat sur tout le cluster.
set -Eeuo pipefail

ADD_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
find_renew_script() {
    local directory name candidate
    for directory in "$ADD_SCRIPT_DIR" "$ADD_SCRIPT_DIR/../bin" \
        "$ADD_SCRIPT_DIR/../sbin" /usr/local/bin /usr/local/sbin; do
        for name in certbot-renew-if-needed.sh certbot-renew-if-needed; do
            candidate="$directory/$name"
            if [[ -f "$candidate" && -r "$candidate" ]]; then
                printf '%s/%s\n' "$(cd -- "$directory" && pwd -P)" "$name"
                return 0
            fi
        done
    done
    for name in certbot-renew-if-needed.sh certbot-renew-if-needed; do
        candidate="$(command -v "$name" || true)"
        if [[ -f "$candidate" && -r "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    return 1
}

if ! ADD_RENEW_PATH="$(find_renew_script)"; then
    echo 'Script de renouvellement introuvable : installer certbot-renew-if-needed.sh dans /usr/local/bin, /usr/local/sbin ou à côté du script d’ajout.' >&2
    exit 1
fi
if ! grep -Fq 'if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then' "$ADD_RENEW_PATH"; then
    echo "Mettre à jour $ADD_RENEW_PATH avec la version du dépôt avant de lancer l’ajout (ancienne version incompatible avec le chargement des fonctions)." >&2
    exit 1
fi
source "$ADD_RENEW_PATH"
ADD_SCRIPT_PATH="$ADD_SCRIPT_DIR/$(basename -- "${BASH_SOURCE[0]}")"

usage() {
    cat <<'HELP'
Usage: certbot-add-domain.sh [domaine] [--backend http[s]://hote[:port]] [--www] [--adopt-existing] [--internal-http-check]

Sans domaine ou backend, le script les demande. --www ajoute www.<domaine>.
Installer les deux scripts dans des répertoires permanents sur chaque proxy.
Le renouvellement peut se trouver dans /usr/local/bin ou /usr/local/sbin.
--adopt-existing reprend un site dédié sans certificat, avec sauvegarde préalable.
--internal-http-check contrôle les jetons via les IP internes des proxies,
pour les réseaux sans accès à leurs propres IP publiques (NAT loopback).
La configuration du cluster est celle de certbot-renew-if-needed.sh.
HELP
}

valid_domain() {
    local domain="$1" label
    local -a labels
    [[ ${#domain} -le 253 && "$domain" == *.* && "$domain" != *..* ]] || return 1
    IFS=. read -r -a labels <<< "$domain"
    [[ "$domain" != *. ]] || return 1
    for label in "${labels[@]}"; do
        [[ ${#label} -le 63 && "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
    done
}

valid_backend() {
    local backend="$1" port
    [[ "$backend" =~ ^https?://([a-z0-9]([a-z0-9.-]*[a-z0-9])?)(:([0-9]{1,5}))?$ ]] || return 1
    port="${BASH_REMATCH[4]:-80}"
    (( 10#$port >= 1 && 10#$port <= 65535 ))
}

certbot_hook_command() {
    # Certaines versions de Certbot découpent le hook sur les espaces sans
    # retirer les guillemets avant de rechercher son exécutable.
    if [[ ! "$ADD_SCRIPT_PATH" =~ ^/[A-Za-z0-9_./-]+$ ]]; then
        echo 'Installer le script d’ajout dans un chemin absolu sans espaces ni caractères spéciaux pour les hooks Certbot.' >&2
        return 1
    fi
    printf '%s %s' "$ADD_SCRIPT_PATH" "$1"
}

# Les arguments SSH sont échappés pour le shell distant ; le programme arrive
# sur stdin. Les commandes exécutées localement utilisent le même programme.
quote_shell() {
    local remaining="$1"
    printf "'"
    while [[ "$remaining" == *"'"* ]]; do
        printf '%s%s' "${remaining%%\'*}" "'\''"
        remaining="${remaining#*\'}"
    done
    printf "%s'" "$remaining"
}

node_run() {
    local host="$1" command argument
    shift
    if [[ "$host" == "$LOCAL_PROXY_IP" ]]; then
        bash -s -- "$@"
    else
        command='bash -s --'
        for argument in "$@"; do command+=" $(quote_shell "$argument")"; done
        ssh "${SSH_OPTS[@]}" -- "$REMOTE_USER@$host" "$command"
    fi
}

node_site() {
    local host="$1" operation="$2" content="${3:-}"
    node_run "$host" "$operation" "$DOMAIN" "$SITE_MARKER" "$content" \
        "$WEBROOT" "$ADD_SCRIPT_PATH" "$ADD_RENEW_PATH" "$SERVER_NAMES" "${ADOPT_EXISTING:-0}" <<'REMOTE'
set -Eeuo pipefail
operation=$1 domain=$2 marker=$3 content=$4 webroot=$5 add_script=$6 renew_script=$7
names=$8
adopt=${9:-0}
available="/etc/nginx/sites-available/$domain"
enabled="/etc/nginx/sites-enabled/$domain"
check_site_names() {
    # Refuser les sites partagés, les inclusions et les noms non demandés.
    awk -v names="$names" '
        BEGIN { count=split(names, wanted, " ") }
        {
            sub(/#.*/, "")
            gsub(/;/, " ; ")
            for (i=1; i<=NF; i++) {
                if ($i == "include") bad=1
                if ($i == "server_name") { reading=1; seen++; continue }
                if (reading) {
                    if ($i == ";") { reading=0; continue }
                    allowed=0
                    for (j=1; j<=count; j++) if ($i == wanted[j]) allowed=1
                    if (!allowed) bad=1
                    entries++
                }
            }
        }
        END { exit (bad || reading || !seen || !entries) ? 1 : 0 }
    ' "$available"
}
case "$operation" in
    preflight)
        for tool in nginx systemctl openssl tar bash; do command -v "$tool" >/dev/null; done
        systemctl is-active --quiet nginx
        nginx -t
        nginx -T 2>/dev/null | awk -v allowed="/etc/nginx/sites-enabled/$domain" -v names="$names" '
            BEGIN { count=split(names, wanted, " ") }
            /^# configuration file / { file=$4; sub(/:$/, "", file) }
            $1 == "server_name" {
                for (i=2; i<=NF; i++) {
                    name=$i; sub(/;$/, "", name)
                    for (j=1; j<=count; j++) {
                        if (name == wanted[j] && file != allowed) {
                            print "Nom déjà configuré dans " file > "/dev/stderr"
                            conflict=1
                        }
                    }
                }
            }
            END { exit conflict ? 1 : 0 }
        '
        test -d /etc/nginx/sites-available
        test -d /etc/nginx/sites-enabled
        # Les hooks enregistrés par Certbot doivent rester disponibles sur les pairs.
        test -x "$add_script"
        test -x "$renew_script"
        test ! -L "$available"
        if [ -e "$available" ]; then
            IFS= read -r first_line < "$available"
            if [ "$first_line" != "$marker" ]; then
                [ "$adopt" -eq 1 ] || { echo "Site existant non géré : $available (reprise explicite : --adopt-existing)" >&2; exit 1; }
                check_site_names || { echo "Reprise refusée : site partagé, inclusion ou noms incompatibles dans $available" >&2; exit 1; }
                if [ -e "/etc/letsencrypt/live/$domain" ] || [ -e "/etc/letsencrypt/renewal/$domain.conf" ]; then
                    echo "Reprise refusée : un certificat existe déjà pour $domain" >&2
                    exit 1
                fi
            fi
        else
            test ! -e "/etc/letsencrypt/live/$domain"
            test ! -e "/etc/letsencrypt/renewal/$domain.conf"
        fi
        if [ -e "$enabled" ] || [ -L "$enabled" ]; then
            test -L "$enabled" && [ "$(readlink -f "$enabled")" = "$available" ]
        fi
        test ! -e "/etc/nginx/conf.d/$domain.conf"
        ;;
    backup)
        if [ -e "$available" ]; then
            saved=$(mktemp -d "/root/backup_add_domain_${domain}_XXXXXX")
            chmod 700 "$saved"
            cp -a "$available" "$saved/site.conf"
            if [ -e "$enabled" ] || [ -L "$enabled" ]; then cp -a "$enabled" "$saved/enabled"; fi
            printf 'Sauvegarde de reprise : %s\n' "$saved"
        fi
        ;;
    install)
        mkdir -p "$webroot/.well-known/acme-challenge"
        chmod 755 "$webroot/.well-known" "$webroot/.well-known/acme-challenge"
        temporary=$(mktemp "${available}.new.XXXXXX")
        backup=""
        had_link=0
        if [ -e "$enabled" ] || [ -L "$enabled" ]; then had_link=1; fi
        if [ -f "$available" ]; then
            backup=$(mktemp "${available}.backup.XXXXXX")
            cp -p "$available" "$backup"
        fi
        rollback() {
            if [ -n "$backup" ]; then mv -f "$backup" "$available"; else rm -f "$available"; fi
            if [ "$had_link" -eq 0 ]; then rm -f "$enabled"; fi
            rm -f "$temporary"
        }
        printf '%s\n' "$content" > "$temporary"
        chmod 644 "$temporary"
        mv -f "$temporary" "$available"
        if [ "$had_link" -eq 0 ]; then ln -s "$available" "$enabled"; fi
        if ! nginx -t; then rollback; exit 1; fi
        if ! systemctl reload nginx; then
            rollback
            nginx -t && systemctl reload nginx || true
            exit 1
        fi
        if [ -n "$backup" ]; then rm -f "$backup"; fi
        ;;
esac
REMOTE
}

render_site() {
    local tls="$1"
    printf '%s\n' "$SITE_MARKER"
    cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAMES;
    server_tokens off;
    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
        default_type "text/plain";
        try_files \$uri =404;
    }
    location / {
EOF
    if [[ "$tls" == https ]]; then
        printf '        return 301 https://$host$request_uri;\n'
    else
        printf '        return 503;\n'
    fi
    printf '    }\n}\n'
    [[ "$tls" == https ]] || return 0
    cat <<EOF
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name $SERVER_NAMES;
    server_tokens off;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
        default_type "text/plain";
        try_files \$uri =404;
    }
    location / {
        proxy_pass $BACKEND;
        proxy_http_version 1.1;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host  \$host;
        proxy_set_header X-Forwarded-Port  \$server_port;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
EOF
}

check_cluster_dns() {
    local name="$1" ip answers ipv6
    answers="$(get_dns_ips "$name" || true)"
    [[ -n "$answers" ]] || die "[$name] Aucun enregistrement A trouvé"
    while IFS= read -r ip; do
        # Comparaison exacte avec l'ensemble des IP publiques du cluster.
        tr ' ' '\n' <<< "$LOCAL_PUBLIC_IPS" | grep -Fxq -- "$ip" \
            || die "[$name] IP DNS hors du cluster configuré : $ip"
    done <<< "$answers"
    ipv6="$(dig @213.186.33.99 +short AAAA "$name" | grep ':' || true)"
    [[ -z "$ipv6" ]] || die "[$name] Enregistrement AAAA détecté : ce script valide uniquement les IP publiques IPv4. Adapter le support IPv6 avant de continuer."
}

# Hook HTTP-01 permanent utilisé aussi par les renouvellements Certbot.
challenge_hook() {
    local action="$1" token="${CERTBOT_TOKEN:-}" host failures=0
    [[ "$token" =~ ^[A-Za-z0-9_-]+$ ]] || { echo 'Jeton ACME invalide' >&2; return 1; }
    local path="$WEBROOT/.well-known/acme-challenge/$token"
    [[ "$path" =~ ^/[a-zA-Z0-9_./-]+$ ]] || return 1
    for host in "${PROXIES[@]}"; do
        if [[ "$action" == auth ]]; then
            [[ "${CERTBOT_VALIDATION:-}" =~ ^[A-Za-z0-9_.-]+$ ]] || return 1
            # Le contenu du jeton reste sur stdin, sans interpolation distante.
            if [[ "$host" == "$LOCAL_PROXY_IP" ]]; then
                mkdir -p "${path%/*}"
                printf '%s' "$CERTBOT_VALIDATION" > "$path"
                chmod 644 "$path"
            elif ! printf '%s' "$CERTBOT_VALIDATION" | ssh "${SSH_OPTS[@]}" \
                -- "$REMOTE_USER@$host" "mkdir -p '${path%/*}' && cat > '$path' && chmod 644 '$path'"; then
                failures=$((failures + 1))
            fi
        else
            if [[ "$host" == "$LOCAL_PROXY_IP" ]]; then
                rm -f -- "$path"
            elif ! ssh -n "${SSH_OPTS[@]}" -- "$REMOTE_USER@$host" "rm -f -- '$path'"; then
                failures=$((failures + 1))
            fi
        fi
    done
    (( failures == 0 ))
}

check_http_routes() {
    local name ip response token curl_status http_status body excerpt
    token="certbot-preflight-$(openssl rand -hex 16)"
    export CERTBOT_TOKEN="$token" CERTBOT_VALIDATION="$token"
    # Nettoyage même si la distribution ou le contrôle HTTP échoue.
    trap 'challenge_hook cleanup || true' EXIT
    challenge_hook auth || die 'Distribution du jeton de contrôle impossible'
    if [[ "${INTERNAL_HTTP_CHECK:-0}" == 1 ]]; then
        log_info 'Contrôle HTTP via les IP internes des proxies ; Let’s Encrypt vérifiera séparément l’accès public.'
    fi
    for name in "${NAMES[@]}"; do
        while IFS= read -r ip; do
            if response="$(curl --noproxy '*' --silent --show-error \
                --connect-timeout 5 --max-time 15 --max-filesize 65536 \
                --write-out $'\n%{http_code}' --resolve "$name:80:$ip" \
                "http://$name/.well-known/acme-challenge/$token")"; then
                curl_status=0
            else
                curl_status=$?
            fi
            http_status="${response##*$'\n'}"
            body="${response%$'\n'*}"
            if (( curl_status != 0 )) || [[ "$http_status" != 200 || "$body" != "$token" ]]; then
                printf -v excerpt '%q' "${body:0:300}"
                log_error "[$name] Contrôle HTTP IP=$ip statut=${http_status:-inconnu} code_curl=$curl_status réponse=$excerpt"
                log_error "[$name] Vérifier le routage/NAT de $ip:80 et le site Nginx qui répond au Host $name ; les jetons sont nettoyés à la sortie."
                die "[$name] Challenge inaccessible sur $ip:80"
            fi
            log_success "[$name] Challenge HTTP vérifié sur $ip:80"
        done < <(
            if [[ "${INTERNAL_HTTP_CHECK:-0}" == 1 ]]; then
                printf '%s\n' "${PROXIES[@]}"
            else
                get_dns_ips "$name"
            fi
        )
    done
    challenge_hook cleanup || die 'Nettoyage du jeton de contrôle incomplet'
    trap - EXIT
    unset CERTBOT_TOKEN CERTBOT_VALIDATION
}

add_domain_main() {
    DOMAIN="" BACKEND=""
    ADOPT_EXISTING=0
    INTERNAL_HTTP_CHECK=0
    local www=0 host name auth_hook cleanup_hook content
    local -a certbot_domains=()
    while (( $# )); do
        case "$1" in
            -h|--help) usage; return 0 ;;
            --www) www=1 ;;
            --adopt-existing) ADOPT_EXISTING=1 ;;
            --internal-http-check) INTERNAL_HTTP_CHECK=1 ;;
            --backend) [[ $# -ge 2 ]] || { usage >&2; return 1; }; BACKEND="$2"; shift ;;
            -*) usage >&2; return 1 ;;
            *) [[ -z "$DOMAIN" ]] || { usage >&2; return 1; }; DOMAIN="$1" ;;
        esac
        shift
    done
    if [[ -z "$DOMAIN" ]]; then
        read -rp 'Nom de domaine : ' DOMAIN
        read -rp 'Ajouter aussi www ? [o/N] : ' name
        [[ "$name" != o && "$name" != O ]] || www=1
    fi
    [[ -n "$BACKEND" ]] || read -rp 'Backend (ex. https://169.0.0.11:443) : ' BACKEND
    valid_domain "$DOMAIN" || { echo 'Domaine invalide (utiliser le format ASCII/punycode).' >&2; return 1; }
    valid_backend "$BACKEND" || { echo 'Backend invalide : utiliser http[s]://hote[:port], sans chemin.' >&2; return 1; }
    auth_hook="$(certbot_hook_command --auth-hook)" || return 1
    cleanup_hook="$(certbot_hook_command --cleanup-hook)" || return 1
    [[ "$WEBROOT" =~ ^/[a-zA-Z0-9_./-]+$ ]] || { echo 'Chemin WEBROOT non pris en charge' >&2; return 1; }
    NAMES=("$DOMAIN")
    if (( www )); then NAMES+=("www.$DOMAIN"); fi
    for name in "${NAMES[@]}"; do
        valid_domain "$name" || { echo "Nom invalide : $name" >&2; return 1; }
    done
    SERVER_NAMES="${NAMES[*]}"
    SITE_MARKER="# Managed by certbot-add-domain: $DOMAIN $BACKEND $SERVER_NAMES"
    check_root
    prepare_environment
    acquire_lock
    check_dependencies
    command -v curl >/dev/null || die 'Commande requise absente : curl'
    LOCAL_PROXY_IP="$(local_ip)" || die 'Exécuter ce script sur un proxy défini dans PROXIES'
    for name in "${NAMES[@]}"; do check_cluster_dns "$name"; done
    for host in "${PROXIES[@]}"; do
        log_info "[$DOMAIN] Précontrôle du proxy $host"
        node_site "$host" preflight || die "Précontrôle échoué sur $host ; aucune configuration déployée"
    done
    if (( ADOPT_EXISTING )); then
        for host in "${PROXIES[@]}"; do
            node_site "$host" backup || die "Sauvegarde échouée sur $host ; aucune configuration déployée"
        done
    fi
    # En reprise, garder le site HTTPS existant si un certificat est déjà présent.
    content="$(render_site http)"
    if [[ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
        for host in "${PROXIES[@]}"; do
            node_site "$host" install "$content" || die "Installation HTTP échouée sur $host ; relancer la même commande après correction"
        done
    fi
    check_http_routes
    for name in "${NAMES[@]}"; do certbot_domains+=(--domain "$name"); done
    # Les hooks sont enregistrés dans renewal/<domaine>.conf par Certbot.
    certbot certonly --manual --preferred-challenges http \
        --manual-auth-hook "$auth_hook" --manual-cleanup-hook "$cleanup_hook" \
        --cert-name "$DOMAIN" --account "$ACCOUNT_ID" --non-interactive --agree-tos \
        "${certbot_domains[@]}" || die "Émission échouée ; le site HTTP est conservé pour une nouvelle tentative"
    validate_local_certificate "$DOMAIN" || die 'Certificat émis invalide'
    for name in "${NAMES[@]}"; do
        openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -noout -checkhost "$name" \
            || die "Le certificat ne couvre pas $name"
    done
    # Certificats d'abord : aucune configuration TLS ne référence un fichier absent.
    for host in "${PROXIES[@]}"; do
        [[ "$host" == "$LOCAL_PROXY_IP" ]] && continue
        sync_cert_to_host_if_needed "$DOMAIN" "$host" proxy || die "Distribution échouée sur $host ; relancer la même commande"
    done
    content="$(render_site https)"
    for host in "${PROXIES[@]}"; do
        node_site "$host" install "$content" || die "Activation HTTPS échouée sur $host ; relancer la même commande"
    done
    log_success "[$DOMAIN] Site HTTPS créé sur les ${#PROXIES[@]} proxies, backend=$BACKEND"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        --auth-hook|--cleanup-hook)
            LOCAL_PROXY_IP="$(local_ip)" || exit 1
            if [[ "$1" == --auth-hook ]]; then challenge_hook auth; else challenge_hook cleanup; fi
            ;;
        *) add_domain_main "$@" ;;
    esac
fi
