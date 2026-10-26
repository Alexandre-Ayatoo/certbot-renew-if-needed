# certbot-renew-if-needed

Script Bash de renouvellement et de synchronisation de certificats Let's Encrypt pour un cluster de proxies Nginx et ses backends.

Il vérifie la durée de validité du certificat local, recherche une version plus récente sur les autres proxies et, si nécessaire, appelle Certbot avec un challenge HTTP-01 en mode webroot. Il distribue ensuite les certificats aux hôtes configurés et recharge Nginx après validation de sa configuration.

## Fonctionnement

Pour chaque domaine, le script :

1. Vérifie la présence du certificat dans `/etc/letsencrypt/live/<domaine>/fullchain.pem`.
2. Normalise un éventuel certificat `<domaine>-000*` dont la date d'expiration est plus éloignée, avec sauvegarde préalable.
3. Vérifie que le certificat local est lisible, non expiré et couvre le domaine demandé.
4. Recherche un certificat dont la date d'expiration est plus éloignée sur les autres proxies.
5. Si le certificat expire dans **15 jours ou moins**, ou avec `--force`, tente un renouvellement local lorsqu'aucune version plus récente n'a été récupérée et que le DNS pointe vers une adresse connue du cluster.
6. Vérifie et synchronise les certificats des proxies, backends et cibles explicites.

Un certificat encore suffisamment valide donne également lieu à une vérification et à une synchronisation du cluster.

## Ajouter un domaine sur les trois proxies

`certbot-add-domain.sh` crée un nouveau site reverse proxy sur tous les membres de `PROXIES`. Il reprend le modèle HTTP/HTTPS avec redirection, exception ACME, en-têtes de proxy et WebSocket. Le domaine et le backend sont demandés s'ils ne sont pas fournis ; en mode entièrement interactif, le script propose aussi d'ajouter `www`.

Installer **les deux scripts à jour sur chacun des proxies**, dans le même répertoire et sous les mêmes noms. Par exemple, depuis le dépôt sur chaque serveur :

```bash
sudo install -m 0750 certbot-renew-if-needed.sh /usr/local/sbin/certbot-renew-if-needed
sudo install -m 0750 certbot-add-domain.sh /usr/local/sbin/certbot-add-domain
```

La configuration du cluster reste en tête de `certbot-renew-if-needed.sh` (ou de sa copie installée sans extension). Les adresses publiques des **trois proxies** doivent figurer dans `LOCAL_PUBLIC_IPS`, et leurs adresses de communication SSH dans `PROXIES`. Les copies installées doivent partager les mêmes paramètres. Le compte `ACCOUNT_ID` doit déjà exister localement sur les proxies susceptibles d'émettre ou renouveler un certificat.

Lancer ensuite l'ajout **une seule fois depuis un proxy** :

```bash
# Questions interactives : domaine, www éventuel et backend
sudo /usr/local/sbin/certbot-add-domain

# Backend demandé à l'exécution, sans www
sudo /usr/local/sbin/certbot-add-domain example.com

# Domaine et www dans un même certificat
sudo /usr/local/sbin/certbot-add-domain example.com \
    --backend https://169.0.0.11 --www
```

Le backend accepte `http://hote[:port]` ou `https://hote[:port]`, sans chemin. `www` n'est ajouté avec un domaine fourni en argument que si `--www` est présent. Il faut que chaque nom demandé ait son DNS prêt.

L'ajout procède ainsi :

1. Vérifie que chaque adresse A publiée pour chaque nom appartient aux IP connues du cluster. Une IP correspondant à un autre proxy est acceptée. Un enregistrement AAAA provoque un arrêt explicite : cette première version contrôle uniquement les adresses publiques IPv4.
2. Vérifie SSH, Nginx actif, les scripts permanents et les conflits de sites sur les trois proxies avant de déployer. Un site existant non créé par ce script est refusé.
3. Installe un site HTTP avec l'emplacement ACME sur les trois proxies. Le reste du site répond temporairement `503`.
4. Distribue un jeton de contrôle sur tous les proxies et vérifie sa lecture HTTP sur chaque IP DNS avec `curl --resolve`.
5. Demande un certificat à Certbot avec des hooks HTTP-01 qui déposent puis nettoient le challenge sur tous les proxies.
6. Vérifie le certificat et tous ses noms, le distribue aux autres proxies, puis active les sites HTTPS et leur redirection HTTP.

Les configurations sont créées dans `sites-available/<domaine>`, avec un lien dans `sites-enabled/<domaine>`. Elles n'utilisent pas les fichiers externes `options-ssl-nginx.conf` et `ssl-dhparams.pem` ; elles déclarent TLS 1.2 et TLS 1.3 directement. Comme le modèle fourni, elles ne configurent pas la vérification du certificat TLS du backend.

L'ajout exige Nginx **actif sur les trois proxies**, car ils doivent servir le challenge HTTP. La copie vers une machine sans Nginx reste possible dans le script de renouvellement. L'ajout initial distribue le certificat aux proxies ; les backends sont pris en compte par les traitements de synchronisation du script de renouvellement selon les directives Nginx.

Une configuration qui échoue à `nginx -t` ou au rechargement est restaurée sur le proxy concerné. Les étapes déjà réussies sur les autres proxies sont conservées : après correction, relancer exactement la même commande (même domaine, backend et option `--www`) permet de reprendre. En cas d'échec de l'émission initiale, le site HTTP est conservé. Le script ne remplace pas une configuration existante créée à la main, y compris l'exemple `alexandre-lb.fr`.

Les hooks sont enregistrés par Certbot avec leur chemin absolu : **ne pas déplacer les scripts après l'émission**. Le script de renouvellement utilise `certbot renew --cert-name` pour les certificats à authentification manuelle afin de conserver les hooks et les noms supplémentaires, dont `www`. Pour les certificats webroot déjà existants, son comportement reste inchangé. Les hooks suivent le mécanisme décrit dans la [documentation Certbot](https://eff-certbot.readthedocs.io/en/stable/using.html#pre-and-post-validation-hooks).

## Prérequis

- Linux avec **Bash 4 ou supérieur**, systemd et Nginx sur le proxy exécutant le script.
- Exécution en **root**.
- Outils GNU, notamment `date --date`, `find -printf` et `grep -P`.
- Certbot installé, avec un compte ACME existant et les certificats à gérer déjà présents.
- OpenSSL avec prise en charge de `x509 -checkhost`.
- Connexions SSH sans interaction vers les autres proxies et les cibles de synchronisation, avec les clés d'hôtes déjà connues et les droits nécessaires sur `/etc/letsencrypt` et Nginx.
- `rsync` installé des deux côtés pour la récupération depuis un pair ; `tar` et les outils utilisés par les commandes distantes disponibles sur les cibles.
- Pour le challenge HTTP-01, le domaine doit permettre l'accès HTTP public au chemin `/.well-known/acme-challenge/` du webroot utilisé par Certbot.

Le script contrôle la présence des commandes suivantes sur le serveur local :

```text
awk certbot cut date dig find flock grep hostname ip logger nginx
openssl rsync sed sort ssh systemctl tail tar tr xargs
```

## Installation

```bash
git clone git@github.com:Alexandre-Ayatoo/certbot-renew-if-needed.git
cd certbot-renew-if-needed
```

Adapter d'abord la configuration en tête de `certbot-renew-if-needed.sh`, puis installer le script :

```bash
sudo install -m 0750 certbot-renew-if-needed.sh /usr/local/sbin/certbot-renew-if-needed
```

Après toute modification du fichier du dépôt, répéter cette commande pour mettre à jour la copie installée.

## Configuration

Les paramètres sont définis directement dans le script. Il ne charge pas de fichier `.env` et ses constantes ne sont pas remplacées par des variables d'environnement.

| Paramètre | Rôle |
| --- | --- |
| `RENEW_BEFORE_DAYS` | Seuil de validité restante avant tentative de renouvellement, fixé à `15` par défaut. |
| `REMOTE_USER` | Utilisateur SSH distant, `root` par défaut. |
| `ACCOUNT_ID` | Identifiant du compte Certbot local à utiliser. |
| `WEBROOT` | Racine du challenge HTTP-01, `/var/www/letsencrypt` par défaut. |
| `PROXIES` | Adresses IPv4 des proxies du cluster. |
| `LOCAL_PUBLIC_IPS` | Adresses reconnues lors du contrôle DNS : adresses locales retournées par `hostname -I` et liste statique à adapter. |
| `SSH_OPTS` | Options SSH : mode non interactif, délai de connexion de 5 secondes et une tentative. |
| `LOCK` | Verrou local : `/var/run/certbot-renew-if-needed.lock`. |
| `LOG` | Journal : `/var/log/certbot-renew-if-needed.log`. |

Les adresses et l'identifiant de compte présents dans le dépôt correspondent à une infrastructure particulière : les remplacer par ceux de l'installation cible. L'adresse locale d'un proxy doit figurer dans `PROXIES` pour qu'il soit identifié et exclu de la liste des pairs distants.

La résolution DNS utilise actuellement le résolveur `213.186.33.99`, défini dans `get_dns_ips()`. Le contrôle porte uniquement sur les enregistrements **A (IPv4)** et réussit dès qu'une des adresses retournées figure dans `LOCAL_PUBLIC_IPS`.

### Challenge HTTP-01 avec Nginx

Ajouter au serveur HTTP du domaine un emplacement correspondant à `WEBROOT`, par exemple :

```nginx
location /.well-known/acme-challenge/ {
    root /var/www/letsencrypt;
    try_files $uri =404;
}
```

Si plusieurs proxies peuvent recevoir la validation ACME, leur routage doit rendre le jeton créé sur le proxy exécutant Certbot accessible. Le script ne distribue pas les fichiers de challenge aux autres proxies.

### Détection des cibles de synchronisation

Pour un domaine donné, le script lit :

- `/etc/nginx/sites-enabled/<domaine>` ;
- `/etc/nginx/sites-available/<domaine>` ;
- tous les fichiers `/etc/nginx/conf.d/*.conf`.

Il extrait les adresses IPv4 des directives actives de ces formes :

```nginx
proxy_pass http://10.0.0.11;
proxy_pass https://10.0.0.12:443;
server 10.0.0.13:443;
```

Pour ajouter une cible sans directive de proxy active :

```nginx
# certbot-sync 10.0.0.14
```

Une directive `proxy_pass` commentée n'ajoute pas de cible. Les noms d'hôtes et les adresses IPv6 ne sont pas extraits. Les fichiers `conf.d/*.conf` sont parcourus pour chaque domaine, sans filtrage par `server_name` : leurs cibles peuvent donc recevoir plusieurs certificats.

## Utilisation

```bash
# Sélection interactive parmi les certificats locaux
sudo /usr/local/sbin/certbot-renew-if-needed

# Traiter un domaine
sudo /usr/local/sbin/certbot-renew-if-needed example.com

# Traiter tous les certificats locaux, hors noms contenant « -000 »
sudo /usr/local/sbin/certbot-renew-if-needed all

# Contourner le seuil de validité restante pour un domaine
sudo /usr/local/sbin/certbot-renew-if-needed example.com --force

# Contourner ce seuil pour tous les domaines
sudo /usr/local/sbin/certbot-renew-if-needed all --force
```

`--force` seul ouvre la sélection interactive avec le seuil désactivé. Cette option conserve la recherche d'un certificat plus récent sur les pairs et le contrôle DNS. Elle ne transmet pas `--force-renewal` à Certbot : celui-ci peut conserver un certificat qu'il juge encore suffisamment valide.

Pour les certificats webroot existants, le script appelle `certbot certonly --webroot` avec un seul `--domain` correspondant au nom demandé : leurs noms supplémentaires ne sont pas reconstruits. Pour les certificats à authentification manuelle, notamment ceux créés par `certbot-add-domain.sh`, il utilise `certbot renew --cert-name` et conserve les noms et hooks enregistrés. Les certificats wildcard nécessitent une validation DNS et ne sont pas pris en charge par le script d'ajout.

## Exécution planifiée

Exemple d'entrée dans la crontab de root (`sudo crontab -e`), après configuration et validation manuelle :

```cron
17 3 * * * /usr/local/sbin/certbot-renew-if-needed all
```

Cette entrée lance un traitement quotidien à 03 h 17, selon le fuseau horaire du serveur. Le verrou `flock` empêche deux instances simultanées **sur le même serveur** ; il ne coordonne pas les exécutions entre proxies.

## Journaux et résultat

Les messages sont envoyés sur la sortie standard, dans le fichier de log et dans syslog avec le tag `certbot-renew-if-needed`.

```bash
sudo tail -f /var/log/certbot-renew-if-needed.log
sudo journalctl -t certbot-renew-if-needed
```

Un traitement réussi retourne `0`. Un échec de traitement ou un verrou déjà détenu retourne un code non nul. En mode `all`, les domaines suivants continuent à être traités après l'échec d'un domaine ; le bilan final indique le total des succès et des erreurs.

## Effets sur les certificats et Nginx

La synchronisation transfère les répertoires `archive/<domaine>`, puis `live/<domaine>` avec leurs liens symboliques, ainsi que la configuration `renewal/<domaine>.conf` lorsqu'elle est disponible. **Les clés privées font partie du transfert** : les hôtes cibles doivent être autorisés à les recevoir.

La normalisation des noms `-000*` peut remplacer les répertoires du certificat canonique et modifier les références dans la configuration Nginx. Elle crée une sauvegarde dans `/root/backup_certbot_normalize_<domaine>_<date>`.

Les copies distantes remplacent les répertoires du domaine ; la récupération depuis un pair utilise `rsync --delete`. Ces opérations ne disposent pas d'un retour arrière automatique. Sur les cibles distantes, Nginx est testé avec `nginx -t` puis rechargé uniquement si son exécutable est présent et son service actif (`systemctl is-active`, ou `service nginx status` en l'absence de systemctl). Si Nginx est absent ou inactif, les certificats restent copiés et vérifiés, sans test de configuration ni rechargement de Nginx, et sans erreur liée à cet état. Un échec du test ou du rechargement d'un service actif reste signalé comme une erreur.

Un certificat local absent ou expiré est refusé avant la recherche sur les pairs et le renouvellement. Le script suppose donc un certificat local existant et encore valide ; la création initiale et la récupération d'un certificat déjà expiré nécessitent une intervention séparée.

## Vérification de syntaxe

```bash
bash -n certbot-renew-if-needed.sh
bash -n certbot-add-domain.sh
```

Cette commande vérifie la syntaxe sans exécuter les opérations. Le script ne propose pas de mode de simulation (`--dry-run`).

Les tests de validation, d'ajout, de hooks ACME, de renouvellement et du traitement Nginx distant utilisent des commandes simulées, sans connexion SSH ni modification du serveur. Ils nécessitent Python 3 :

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```
