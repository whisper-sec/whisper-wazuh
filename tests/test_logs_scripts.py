"""#35 — install.sh/uninstall.sh with the --logs block: POSIX-sh clean + symmetric markers."""

import subprocess
from pathlib import Path

WHISPER = Path(__file__).resolve().parent.parent / 'integrations' / 'whisper'
INSTALL = WHISPER / 'install.sh'
UNINSTALL = WHISPER / 'uninstall.sh'


def _text(p):
    return p.read_text()


class TestSyntaxWithLogsBlock:
    def test_install_parses(self):
        r = subprocess.run(['sh', '-n', str(INSTALL)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr

    def test_uninstall_parses(self):
        r = subprocess.run(['sh', '-n', str(UNINSTALL)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


class TestLogsFlag:
    def test_logs_flag_parsed(self):
        assert '--logs)          LOGS_MODE=1' in _text(INSTALL)

    def test_logs_required_files_gated(self):
        t = _text(INSTALL)
        assert 'whisper-logs whisper-logs.py whisper_agent_rules.xml' in t

    def test_logs_marker_block_managed(self):
        t = _text(INSTALL)
        assert 'whisper-logs:begin' in t and 'whisper-logs:end' in t
        # rendered before the FIRST standalone </ossec_config>, like the enrichment block
        assert 'localfile' in t and 'whisper-agent-activity.json' in t
        assert 'wodle name=\\"command\\"' in t and 'whisper-logs' in t

    def test_logs_block_independent_of_enrichment_block(self):
        """The two managed blocks use distinct markers so one can be removed without the other."""
        t = _text(INSTALL)
        assert 'whisper-integration:begin' in t  # enrichment block untouched
        assert 'whisper-logs:begin' in t  # separate log-source block

    def test_default_install_leaves_enrichment_identical(self):
        """LOGS_MODE defaults to 0 — a plain install installs no log-source pieces."""
        assert 'LOGS_MODE=0' in _text(INSTALL)


class TestUninstallSymmetry:
    def test_removes_logs_marker_block(self):
        t = _text(UNINSTALL)
        assert 'whisper-logs:begin' in t and 'whisper-logs:end' in t
        assert 'marker block survived removal' in t  # verified removal, aborts if it lingers

    def test_removes_logs_files(self):
        t = _text(UNINSTALL)
        assert 'integrations/whisper-logs' in t
        assert 'etc/rules/whisper_agent_rules.xml' in t

    def test_purge_removes_spool_and_cursor(self):
        t = _text(UNINSTALL)
        assert 'logs-cursor' in t
        assert 'whisper-agent-activity.json' in t

    def test_ossec_write_in_place_for_logs_block(self):
        # in-place write preserves the inode (a root:root ossec.conf breaks the manager)
        assert 'cat "$TMP_CONF" > "$OSSEC_CONF"' in _text(UNINSTALL)


class TestNoSecretsOnCmdline:
    def test_no_api_key_literal(self):
        for p in (INSTALL, UNINSTALL):
            t = _text(p)
            assert 'whisper_live_' not in t
            # the key is only ever referenced via the key file / env, never inlined
            assert 'X-API-Key' not in t
