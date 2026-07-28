#!/bin/sh
cat <<'MSG'

whisper-wazuh: files installed to /usr/share/whisper-wazuh.

This did NOT auto-activate — install patches ossec.conf, pushes the indexer template, and
restarts the manager, which is an explicit admin step (and needs your trigger groups + API key),
not something a package postinstall should do unattended.

Activate on THIS Wazuh manager (as root):

    whisper-wazuh-install --group sshd --api-key-file /path/to/your-whisper-key.txt

Remove later with:  whisper-wazuh-uninstall
MSG
