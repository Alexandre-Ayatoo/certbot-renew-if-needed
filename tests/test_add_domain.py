"""Cluster/domain tests without SSH, Nginx changes or ACME requests."""

import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class AddDomainTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.webroot = self.root / "webroot"
        renewal = (ROOT / "certbot-renew-if-needed.sh").read_text().replace(
            "/var/www/letsencrypt", str(self.webroot)
        ).replace("/etc/letsencrypt", str(self.root / "letsencrypt"))
        (self.root / "certbot-renew-if-needed.sh").write_text(renewal)
        shutil.copy(ROOT / "certbot-add-domain.sh", self.root)

    def shell(self, body, **environment):
        return subprocess.run(
            ["/bin/bash", "-c", "source " + shlex.quote(str(self.root / "certbot-add-domain.sh")) + "\n" + body],
            env=dict(os.environ, **environment), capture_output=True, text=True,
        )

    def test_input_validation(self):
        for value in ("example.com", "www.example.com", "xn--caf-dma.fr"):
            self.assertEqual(self.shell("valid_domain " + shlex.quote(value)).returncode, 0)
        for value in ("-bad.com", "bad;.com", "*.example.com", "a..com", "example.com.", "a" * 64 + ".com"):
            self.assertNotEqual(self.shell("valid_domain " + shlex.quote(value)).returncode, 0)
        for value in ("https://169.0.0.11", "http://backend.local:8080"):
            self.assertEqual(self.shell("valid_backend " + shlex.quote(value)).returncode, 0)
        for value in ("https://host/path", "http://host:0", "http://host:65536", "http://host;id"):
            self.assertNotEqual(self.shell("valid_backend " + shlex.quote(value)).returncode, 0)

    def test_separate_bin_and_sbin_installation(self):
        binaries = self.root / "bin"
        system_binaries = self.root / "sbin"
        binaries.mkdir()
        system_binaries.mkdir()
        renewal = binaries / "certbot-renew-if-needed.sh"
        (self.root / "certbot-renew-if-needed.sh").rename(renewal)
        addition = system_binaries / "certbot-add-domain"
        shutil.copy(self.root / "certbot-add-domain.sh", addition)
        result = subprocess.run(
            ["/bin/bash", "-c", "source " + shlex.quote(str(addition)) + '\nprintf "%s" "$ADD_RENEW_PATH"'],
            capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, str(renewal.resolve()))

    def test_old_renewal_script_is_not_executed_when_sourced(self):
        (self.root / "certbot-renew-if-needed.sh").write_text("echo OLD_SCRIPT_EXECUTED\n")
        result = self.shell(":")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("OLD_SCRIPT_EXECUTED", result.stdout)
        self.assertIn("Mettre à jour", result.stderr)

    def test_ssh_arguments_survive_a_posix_remote_shell(self):
        value = "configuration\nwith 'quotes' and $literal; $(commands)"
        result = self.shell('''
LOCAL_PROXY_IP=169.0.0.21
ssh() { /bin/sh -c "${!#}"; }
node_run 169.0.0.22 "$VALUE" <<'REMOTE'
printf '%s' "$1"
REMOTE
''', VALUE=value)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, value)

    def test_certbot_hook_executable_needs_no_quote_parsing(self):
        for mode in ("--auth-hook", "--cleanup-hook"):
            with self.subTest(mode=mode):
                result = self.shell("certbot_hook_command " + mode)
                self.assertEqual(result.returncode, 0, result.stderr)
                # Reproduire la recherche de l’exécutable sans interprétation
                # des guillemets, effectuée par les versions concernées.
                executable, argument = result.stdout.split()
                self.assertTrue(Path(executable).is_file())
                self.assertTrue(os.access(executable, os.X_OK))
                self.assertEqual(argument, mode)
        result = self.shell("ADD_SCRIPT_PATH='/path with spaces/add'; certbot_hook_command --auth-hook")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_dns_accepts_other_proxies_and_rejects_unknown_addresses(self):
        setup = '''
die() { echo "$*" >&2; exit 1; }
dig() { :; }
get_dns_ips() { printf '%s\\n' 51.75.129.105 51.75.129.106; }
'''
        self.assertEqual(self.shell(setup + "check_cluster_dns example.com").returncode, 0)
        result = self.shell(setup + '''
get_dns_ips() { printf '%s\\n' 51.75.129.105 192.0.2.123; }
check_cluster_dns example.com
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("192.0.2.123", result.stderr)
        self.assertNotEqual(self.shell(setup + '''
dig() { echo 2001:db8::1; }
check_cluster_dns example.com
''').returncode, 0)

    def test_nginx_templates(self):
        setup = '''
DOMAIN=example.com BACKEND=https://169.0.0.11
SERVER_NAMES='example.com www.example.com'
SITE_MARKER='# Managed by certbot-add-domain: test'
'''
        http = self.shell(setup + "render_site http")
        self.assertEqual(http.returncode, 0, http.stderr)
        self.assertIn("location ^~ /.well-known/acme-challenge/", http.stdout)
        self.assertNotIn("ssl_certificate", http.stdout)
        tls = self.shell(setup + "render_site https")
        self.assertEqual(tls.returncode, 0, tls.stderr)
        self.assertIn("server_name example.com www.example.com;", tls.stdout)
        self.assertIn("return 301 https://$host$request_uri;", tls.stdout)
        self.assertIn("proxy_pass https://169.0.0.11;", tls.stdout)
        self.assertIn("proxy_set_header Host              $host;", tls.stdout)

    def test_adoption_rejects_other_domains_and_includes(self):
        remote = (ROOT / "certbot-add-domain.sh").read_text().split("<<'REMOTE'\n", 1)[1].split("\nREMOTE", 1)[0]
        declarations = remote.split('case "$operation" in', 1)[0]
        site = self.root / "existing.conf"
        for content, accepted in (
            ("server {\n server_name example.com;\n}\n", True),
            ("server_name\n example.com\n www.example.com;\n", True),
            ("server_name example.com unrelated.com;\n", False),
            ("server_name example.com;\ninclude /etc/nginx/other.conf;\n", False),
            ("server_name _;\n", False),
            ("# server_name example.com;\n", False),
        ):
            with self.subTest(content=content):
                site.write_text(content)
                result = subprocess.run(
                    ["/bin/bash", "-c", declarations + '\navailable="$FIXTURE"\ncheck_site_names',
                     "remote", "preflight", "example.com", "marker", "", str(self.webroot),
                     "add", "renew", "example.com www.example.com", "1"],
                    env=dict(os.environ, FIXTURE=str(site)), capture_output=True, text=True,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_challenge_distribution_cleanup_and_peer_failure(self):
        setup = '''
LOCAL_PROXY_IP=169.0.0.21
CERTBOT_TOKEN=test-token CERTBOT_VALIDATION=challenge.value
ssh() {
    case "$*" in
        *'cat >'*) cat >> "$CAPTURE" ;;
        *) : ;;
    esac
}
'''
        capture = self.root / "uploads"
        result = self.shell(setup + "challenge_hook auth", CAPTURE=str(capture))
        self.assertEqual(result.returncode, 0, result.stderr)
        token = self.webroot / ".well-known/acme-challenge/test-token"
        self.assertEqual(token.read_text(), "challenge.value")
        self.assertEqual(capture.read_text(), "challenge.value" * 2)
        result = self.shell(setup + "challenge_hook cleanup", CAPTURE=str(capture))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(token.exists())
        self.assertNotEqual(self.shell(setup + "ssh() { return 1; }; challenge_hook auth").returncode, 0)
        self.assertNotEqual(self.shell(setup + "CERTBOT_TOKEN=../bad; challenge_hook auth").returncode, 0)

    def test_issuance_failure_never_activates_tls(self):
        result = self.shell('''
check_root() { :; }; prepare_environment() { :; }
acquire_lock() { :; }; check_dependencies() { :; }
local_ip() { echo 169.0.0.21; }
check_cluster_dns() { :; }
log_info() { :; }; log_success() { echo SUCCESS; }
die() { echo "$*" >&2; exit 1; }
node_site() { echo "NODE:$1:$2"; }
check_http_routes() { echo HTTP_CHECKED; }
certbot() { echo CERTBOT_FAILED; return 1; }
add_domain_main example.com --backend https://169.0.0.11 --www
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout.count(":preflight"), 3)
        self.assertEqual(result.stdout.count(":install"), 3)
        self.assertIn("HTTP_CHECKED", result.stdout)
        self.assertNotIn("SUCCESS", result.stdout)

    def test_manual_renewal_preserves_hooks_and_names(self):
        config = self.root / "letsencrypt/renewal"
        config.mkdir(parents=True)
        (config / "example.com.conf").write_text("authenticator = manual\n")
        result = self.shell('''
log_info() { :; }; log_error() { :; }; log_success() { :; }
certbot() { printf '%s\\n' "$*" > "$CAPTURE"; }
normalize_cert_name() { :; }; validate_local_certificate() { :; }
test_and_reload_nginx() { :; }
renew_local_cert example.com
''', CAPTURE=str(self.root / "arguments"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "arguments").read_text(), "renew --cert-name example.com --non-interactive\n")

    def test_success_distributes_certificates_before_tls_activation(self):
        result = self.shell('''
check_root() { :; }; prepare_environment() { :; }
acquire_lock() { :; }; check_dependencies() { :; }
local_ip() { echo 169.0.0.21; }
check_cluster_dns() { :; }
log_info() { :; }; log_success() { echo SUCCESS; }
die() { echo "$*" >&2; exit 1; }
node_site() {
    local stage=http
    [[ "${3:-}" != *'ssl_certificate '* ]] || stage=https
    echo "NODE:$1:$2:$stage"
}
check_http_routes() { echo HTTP_CHECKED; }
certbot() {
    local previous='' argument executable
    for argument in "$@"; do
        if [[ "$previous" == --manual-auth-hook || "$previous" == --manual-cleanup-hook ]]; then
            executable="${argument%% *}"
            [[ -x "$executable" ]] || return 99
        fi
        previous="$argument"
    done
    echo "CERTBOT:$*"
}
openssl() { :; }; validate_local_certificate() { :; }
sync_cert_to_host_if_needed() { echo "COPY:$2"; }
add_domain_main example.com --backend https://169.0.0.11 --www --adopt-existing
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        backups = [i for i, line in enumerate(lines) if ":backup:" in line]
        installs = [i for i, line in enumerate(lines) if ":install:" in line]
        self.assertEqual(len(backups), 3)
        self.assertLess(max(backups), min(installs))
        copies = [i for i, line in enumerate(lines) if line.startswith("COPY:")]
        tls = [i for i, line in enumerate(lines) if line.endswith(":install:https")]
        self.assertEqual(len(copies), 2)
        self.assertEqual(len(tls), 3)
        self.assertLess(max(copies), min(tls))
        self.assertIn("--domain example.com --domain www.example.com", result.stdout)
        self.assertIn("--manual-auth-hook", result.stdout)
        self.assertEqual(lines[-1], "SUCCESS")

    def test_preflight_failure_makes_no_site_changes(self):
        result = self.shell('''
check_root() { :; }; prepare_environment() { :; }
acquire_lock() { :; }; check_dependencies() { :; }
local_ip() { echo 169.0.0.21; }; check_cluster_dns() { :; }
log_info() { :; }; die() { exit 1; }
node_site() { echo "$2"; [[ "$1" != 169.0.0.22 ]]; }
add_domain_main example.com --backend https://169.0.0.11
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("install", result.stdout)

    def test_failed_http_probe_cleans_up_challenge(self):
        result = self.shell('''
LOCAL_PROXY_IP=169.0.0.21
NAMES=(example.com)
openssl() { echo abcdef123456; }
ssh() { case "$*" in *'cat >'*) cat >/dev/null ;; *) : ;; esac; }
get_dns_ips() { echo 51.75.129.105; }
curl() { printf 'WRONG_TOKEN\\n200'; }
log_error() { echo "$*" >&2; }
die() { echo "$*" >&2; exit 1; }
check_http_routes
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Challenge inaccessible", result.stderr)
        self.assertIn("statut=200", result.stderr)
        self.assertIn("réponse=WRONG_TOKEN", result.stderr)
        self.assertFalse((self.webroot / ".well-known/acme-challenge/certbot-preflight-abcdef123456").exists())

    def test_http_probe_accepts_only_exact_token_with_status_200(self):
        setup = '''
LOCAL_PROXY_IP=169.0.0.21
NAMES=(example.com)
openssl() { echo abcdef123456; }
ssh() { case "$*" in *'cat >'*) cat >/dev/null ;; *) : ;; esac; }
get_dns_ips() { printf '%s\\n' 51.75.129.105 51.75.129.106; }
log_error() { echo "$*" >&2; }; log_success() { :; }
die() { echo "$*" >&2; exit 1; }
'''
        for status in ("200", "301", "404"):
            with self.subTest(status=status):
                result = self.shell(setup + '''
curl() { printf '%s\\n%s' "$CERTBOT_VALIDATION" "$STATUS"; }
check_http_routes
''', STATUS=status)
                self.assertEqual(result.returncode == 0, status == "200", result.stderr)
                if status != "200":
                    self.assertIn("statut=" + status, result.stderr)

    def test_internal_http_check_verifies_every_proxy(self):
        capture = self.root / "http-targets"
        result = self.shell('''
LOCAL_PROXY_IP=169.0.0.21
INTERNAL_HTTP_CHECK=1
NAMES=(example.com)
openssl() { echo abcdef123456; }
ssh() { case "$*" in *'cat >'*) cat >/dev/null ;; *) : ;; esac; }
get_dns_ips() { echo 51.75.129.105; }
log_error() { echo "$*" >&2; }; log_success() { :; }; log_info() { :; }
die() { echo "$*" >&2; exit 1; }
curl() {
    while (( $# )); do
        if [[ "$1" == --resolve ]]; then printf '%s\\n' "$2" >> "$CAPTURE"; fi
        shift
    done
    printf '%s\\n200' "$CERTBOT_VALIDATION"
}
check_http_routes
''', CAPTURE=str(capture))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(capture.read_text().splitlines(), [
            "example.com:80:169.0.0.21", "example.com:80:169.0.0.22", "example.com:80:169.0.0.23",
        ])

    def test_invalid_nginx_configuration_restores_previous_site(self):
        # Exécuter le vrai programme distant dans une arborescence temporaire.
        remote = (ROOT / "certbot-add-domain.sh").read_text().split("<<'REMOTE'\n", 1)[1].split("\nREMOTE", 1)[0]
        nginx_root = self.root / "nginx"
        remote = remote.replace("/etc/nginx", str(nginx_root))
        available = nginx_root / "sites-available"
        enabled = nginx_root / "sites-enabled"
        available.mkdir(parents=True)
        enabled.mkdir()
        binaries = self.root / "bin"
        binaries.mkdir()
        (binaries / "nginx").write_text("#!/bin/sh\nexit 1\n")
        (binaries / "nginx").chmod(0o755)
        (binaries / "systemctl").write_text("#!/bin/sh\necho UNEXPECTED_RELOAD >&2\nexit 1\n")
        (binaries / "systemctl").chmod(0o755)
        site = available / "example.com"
        link = enabled / "example.com"
        for existing in (False, True):
            with self.subTest(existing=existing):
                if existing:
                    site.write_text("previous configuration\n")
                    link.symlink_to(site)
                result = subprocess.run(
                    ["/bin/bash", "-c", remote, "remote", "install", "example.com",
                     "marker", "invalid configuration", str(self.webroot), "add", "renew", "example.com"],
                    env=dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ["PATH"]),
                    capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("UNEXPECTED_RELOAD", result.stderr)
                if existing:
                    self.assertEqual(site.read_text(), "previous configuration\n")
                    self.assertTrue(link.is_symlink())
                else:
                    self.assertFalse(site.exists())
                    self.assertFalse(link.is_symlink())
                self.assertFalse(list(available.glob("*.backup.*")))
                self.assertFalse(list(available.glob("*.new.*")))


if __name__ == "__main__":
    unittest.main()
