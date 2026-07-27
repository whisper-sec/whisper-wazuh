"""#18 — install.sh / uninstall.sh: POSIX-sh syntax + safety invariants.

These scripts run as root on a manager and edit ossec.conf, so they can't rely on live
integration testing alone — a few structural guardrails catch regressions in CI.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WHISPER = ROOT / 'integrations' / 'whisper'
INSTALL = WHISPER / 'install.sh'
UNINSTALL = WHISPER / 'uninstall.sh'


def _text(p):
    return p.read_text()


class TestSyntax:
    def test_install_parses_as_posix_sh(self):
        # `sh -n` = parse-only; catches bashisms the manager's /bin/sh (dash/busybox) would reject
        r = subprocess.run(['sh', '-n', str(INSTALL)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    def test_uninstall_parses_as_posix_sh(self):
        r = subprocess.run(['sh', '-n', str(UNINSTALL)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    def test_release_scripts_parse_as_posix_sh(self):
        """bootstrap.sh + the packaging wrappers (#42) run on strangers' hosts — keep them
        POSIX-sh clean so /bin/sh (dash/busybox) doesn't choke on a bashism."""
        for rel in (
            'bootstrap.sh',
            'packaging/whisper-wazuh-install',
            'packaging/whisper-wazuh-uninstall',
            'packaging/postinstall.sh',
        ):
            r = subprocess.run(['sh', '-n', str(ROOT / rel)], capture_output=True, text=True)
            assert r.returncode == 0, f'{rel}: {r.stderr}'


class TestSafetyInvariants:
    def test_no_password_on_curl_cmdline(self):
        """The indexer credential must go via `curl -K -` (stdin), never `-u user:pass`
        (visible in ps/proc) — the scripts' own secret-handling policy."""
        for p in (INSTALL, UNINSTALL):
            for line in _text(p).splitlines():
                stripped = line.strip()
                if stripped.startswith('#'):
                    continue
                assert '-u "$INDEXER_USER_ARG:$INDEXER_PASS_ARG"' not in line, p.name

    def test_install_has_rollback_trap(self):
        t = _text(INSTALL)
        assert 'trap cleanup EXIT INT TERM' in t
        assert 'ROLLBACK_CONF' in t  # armed around the ossec.conf write

    def test_ossec_write_is_in_place(self):
        """Must overwrite ossec.conf in place (cat >), not mv — mv changes the inode and can
        break perms/hardlinks; a root:root conf breaks the manager."""
        t = _text(INSTALL)
        assert 'cat "$TMP_CONF" > "$OSSEC_CONF"' in t
        assert 'mv ' not in t  # never mv onto ossec.conf

    def test_reasserts_ossec_ownership(self):
        # every path that writes ossec.conf must restore root:wazuh 660
        for p in (INSTALL, UNINSTALL):
            t = _text(p)
            assert 'chown root:wazuh "$OSSEC_CONF"' in t
            assert 'chmod 660 "$OSSEC_CONF"' in t

    def test_template_put_before_manager_mutation(self):
        """Ordering: the template PUT (section 0) must precede the file/ossec.conf writes
        so an unreachable indexer aborts before the manager is touched."""
        t = _text(INSTALL)
        put_pos = t.index('_template/whisper')
        cp_pos = t.index('installing integration script')
        assert put_pos < cp_pos

    def test_loop_guard_lists_all_emitted_groups(self):
        """The --group loop-guard must reject every group the enrichment rules carry."""
        t = _text(INSTALL)
        for g in (
            'whisper_enrichment',
            'whisper_known_bad',
            'whisper_suspicious',
            'whisper_known_good',
            'whisper_unknown',
            'whisper_c2',
        ):
            assert g in t

    def test_dev_precondition_covers_test_rule(self):
        """--dev copies whisper_test_rules.xml, so it must be added to the existence
        precondition (else a missing file slips through to an ossec.conf patch)."""
        t = _text(INSTALL)
        assert 'REQUIRED="$REQUIRED whisper_test_rules.xml"' in t

    def test_refresh_index_requires_dev(self):
        assert '--refresh-index requires --dev' in _text(INSTALL)

    def test_api_key_file_option(self):
        """--api-key-file (#42) installs the key FROM A FILE — never on argv — into the key
        file at 640 root:wazuh, and rejects an empty/placeholder file."""
        t = _text(INSTALL)
        assert '--api-key-file' in t and 'API_KEY_FILE_ARG' in t
        assert 'chmod 640 "$KEY_FILE"' in t
        assert 'empty or holds the placeholder' in t
        # the key content must come from the FILE, not a bare argv value (no `--api-key)` handler)
        assert '--api-key)' not in t

    def test_required_includes_shared_module_and_cli(self):
        """The connector ImportErrors without whisper_client.py, and the on-demand CLI (#33)
        must ship too — install.sh copies an explicit list, so both must be in REQUIRED and the
        cp block (else a runtime ImportError / missing tool on the manager)."""
        t = _text(INSTALL)
        for f in ('whisper_client.py', 'whisper-investigate', 'whisper-investigate.py'):
            assert 'REQUIRED=' in t and f in t.split('REQUIRED=', 1)[1].split('\n', 1)[0], f
            assert f in t  # also copied/chowned
        # uninstall removes them
        u = _text(UNINSTALL)
        for f in ('whisper_client.py', 'whisper-investigate', 'whisper-investigate.py'):
            assert f in u, f
