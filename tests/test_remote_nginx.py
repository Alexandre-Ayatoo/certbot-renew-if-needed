"""Exercise the actual post-copy SSH command with simulated remote services."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "certbot-renew-if-needed.sh"
COPY_FUNCTION = SCRIPT.read_text().split("copy_cert_to_host() {", 1)[1].split(
    "sync_cert_to_host_if_needed() {", 1
)[0]
REMOTE_COMMAND = re.findall(
    r'            ("\n                set -e\n.*?\n            ") 2>&1',
    COPY_FUNCTION.rsplit('if ! remote_output="$(', 1)[1],
    re.DOTALL,
)[-1]


class RemoteNginxTests(unittest.TestCase):
    def run_remote(self, *, nginx=True, manager="systemctl", active=True,
                   config_ok=True, reload_ok=True):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = root / "calls"
            commands = {
                "sed": 'printf "sed\\n" >> "$CALLS"\n',
            }
            if nginx:
                commands["nginx"] = (
                    'printf "nginx %s\\n" "$*" >> "$CALLS"\n'
                    'if [ "$1" = "-t" ]; then exit "$CONFIG_STATUS"; fi\n'
                    'exit "$RELOAD_STATUS"\n'
                )
            if manager:
                commands[manager] = (
                    f'printf "{manager} %s\\n" "$*" >> "$CALLS"\n'
                    'case "$*" in\n'
                    '  *is-active*|*status*) exit "$ACTIVE_STATUS" ;;\n'
                    '  *) exit "$RELOAD_STATUS" ;;\n'
                    'esac\n'
                )
            for name, body in commands.items():
                executable = root / name
                executable.write_text("#!/bin/sh\n" + body)
                executable.chmod(0o755)
            env = dict(os.environ, PATH=directory, CALLS=str(calls),
                       CONFIG_STATUS=str(0 if config_ok else 1),
                       ACTIVE_STATUS=str(0 if active else 3),
                       RELOAD_STATUS=str(0 if reload_ok else 1))
            result = subprocess.run(
                ["/bin/bash", "-c", 'domain=example.com\n/bin/bash -c ' + REMOTE_COMMAND],
                env=env, capture_output=True, text=True,
            )
            return result, calls.read_text() if calls.exists() else ""

    def test_active_service_is_tested_and_reloaded(self):
        for manager, reload_command in (
            ("systemctl", "systemctl reload nginx"),
            ("service", "nginx -s reload"),
        ):
            with self.subTest(manager=manager):
                result, calls = self.run_remote(manager=manager)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("nginx -t\n", calls)
                self.assertIn(reload_command, calls)
                self.assertIn("CERTBOT_REMOTE_STATUS=NGINX_RELOADED\n", result.stdout)

    def test_absent_or_inactive_service_skips_nginx_operations(self):
        for options in (
            {"nginx": False},
            {"active": False},
            {"manager": "service", "active": False},
            {"manager": None},
        ):
            with self.subTest(options=options):
                result, calls = self.run_remote(**options)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("sed\n", calls)
                self.assertNotIn("nginx -t", calls)
                self.assertNotIn("reload", calls)
                self.assertIn("NGINX_ABSENT_OR_INACTIVE\n", result.stdout)

    def test_active_service_errors_are_preserved(self):
        for options in ({"config_ok": False}, {"reload_ok": False}):
            with self.subTest(options=options):
                result, calls = self.run_remote(**options)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("NGINX_RELOADED", result.stdout)
                if not options.get("config_ok", True):
                    self.assertNotIn("reload", calls)


if __name__ == "__main__":
    unittest.main()
