# whisper-wazuh — developer convenience targets.
# Wraps the local single-node Wazuh dev stack under dev/wazuh-single-node/.

SHELL := /usr/bin/env bash

STACK_DIR    := dev/wazuh-single-node
CERT_DIR     := $(STACK_DIR)/config/certs
COMPOSE      := docker compose -f $(STACK_DIR)/docker-compose.yml -f $(STACK_DIR)/docker-compose.traefik.yml
COMPOSE_BASE := docker compose -f $(STACK_DIR)/docker-compose.yml
COMPOSE_AGENT := $(COMPOSE) -f $(STACK_DIR)/docker-compose.agent.yml

.DEFAULT_GOAL := help

.PHONY: help dev-init dev-certs dev-up dev-up-basic dev-down dev-reset dev-restart dev-ps dev-logs \
        dev-agent-up dev-agent-down dev-agent-logs dev-agent-demo \
        dev-whisper-install dev-whisper-uninstall dev-whisper-smoke dev-demo-enrich dev-acceptance \
        dev-logs-install dev-logs-smoke \
        dev5-certs dev5-up dev5-down dev5-reset dev5-ps dev5-whisper-install \
        dev5-agent-up dev5-agent-down dev5-agent-demo dev5-spike-setup dev5-spike-up dev5-spike-query

help: ## Show available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

dev-init: ## One-time setup: dev cert + /etc/hosts + trust CA (uses sudo)
	cd $(STACK_DIR) && ./scripts/dev-init.sh

dev-certs: ## Generate the Wazuh indexer TLS certs
	cd $(STACK_DIR) && docker compose -f generate-indexer-certs.yml run --rm generator

dev-up: ## Start the stack with Traefik domain access (run dev-init first)
	@test -f $(CERT_DIR)/wildcard.crt \
		|| { echo "Traefik cert missing — run 'make dev-init' first."; exit 1; }
	$(COMPOSE) up -d

dev-up-basic: ## Start the stack without Traefik (localhost ports only)
	@test -f $(CERT_DIR)/root-ca.pem || $(MAKE) dev-certs
	$(COMPOSE_BASE) up -d

dev-down: ## Stop the stack incl. agent (keep data volumes)
	$(COMPOSE_AGENT) down

dev-reset: ## Stop the stack and wipe all data volumes
	$(COMPOSE_AGENT) down -v

dev-restart: ## Restart the stack
	$(COMPOSE_AGENT) restart

dev-ps: ## Show stack status
	$(COMPOSE_AGENT) ps

dev-logs: ## Follow stack logs
	$(COMPOSE_AGENT) logs -f

dev-agent-up: ## Add an enrolled Wazuh agent (generates real alerts)
	$(COMPOSE_AGENT) up -d wazuh.agent

dev-agent-down: ## Remove the Wazuh agent
	$(COMPOSE_AGENT) rm -sf wazuh.agent

dev-agent-logs: ## Follow the agent logs
	$(COMPOSE_AGENT) logs -f wazuh.agent

dev-agent-demo: ## Inject a sample SSH brute-force alert (IOC) via the agent
	@$(COMPOSE_AGENT) exec -T wazuh.agent sh -c \
		'touch /var/log/wazuh-demo.log; echo "$$(date "+%b %e %H:%M:%S") server sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 4444 ssh2" >> /var/log/wazuh-demo.log'
	@echo "Injected SSH brute-force from 203.0.113.45 — expect rule 5710 in the dashboard/indexer (~1 min on first run)."
	@echo "NOTE: 203.0.113.45 is TEST-NET-3 (non-global) — the Whisper connector deliberately skips it."

# --- Whisper connector (integrations/whisper/) -------------------------------------------
WHISPER_SRC := /var/ossec/tmp/whisper-src

dev-whisper-install: ## Install the Whisper connector into the dev manager (dev mode)
	$(COMPOSE_BASE) exec -T wazuh.manager mkdir -p $(WHISPER_SRC)
	docker cp integrations/whisper/. $$($(COMPOSE_BASE) ps -q wazuh.manager):$(WHISPER_SRC)/
	$(COMPOSE_BASE) exec -T wazuh.manager sh $(WHISPER_SRC)/install.sh --dev --group sshd --refresh-index
	@echo "Installed. Put a real API key in /var/ossec/etc/whisper.key (or set WHISPER_API_KEY) for live enrichment."

dev-whisper-uninstall: ## Remove the Whisper connector and restore ossec.conf
	$(COMPOSE_BASE) exec -T wazuh.manager mkdir -p $(WHISPER_SRC)
	docker cp integrations/whisper/. $$($(COMPOSE_BASE) ps -q wazuh.manager):$(WHISPER_SRC)/
	$(COMPOSE_BASE) exec -T wazuh.manager sh $(WHISPER_SRC)/uninstall.sh

dev-whisper-smoke: ## Inject 3 IOC scenarios and show the connector's log evidence
	@$(COMPOSE_BASE) exec -T wazuh.manager sh -c "grep -q 'integrator.debug' /var/ossec/etc/local_internal_options.conf 2>/dev/null || { echo 'integrator.debug=2' >> /var/ossec/etc/local_internal_options.conf; /var/ossec/bin/wazuh-control restart >/dev/null 2>&1; sleep 5; }"
	@echo "--- injecting: public Tor IP (invoke), private IP (skip), TEST-NET demo IOC (skip) ---"
	@$(COMPOSE_BASE) exec -T wazuh.manager /var/ossec/framework/python/bin/python3 -c "\
	import socket,time; \
	send=lambda ip: (lambda s: (s.connect('/var/ossec/queue/sockets/queue'), s.send(('1:whisper-smoke:'+time.strftime('%b %e %H:%M:%S')+' host sshd[9]: Failed password for invalid user smoke from '+ip+' port 4444 ssh2').encode()), s.close()))(socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)); \
	send('185.220.101.1'); send('10.0.0.5'); send('203.0.113.45')"
	@sleep 8
	@echo "--- connector log evidence (integrations.log) ---"
	@$(COMPOSE_BASE) exec -T wazuh.manager sh -c "grep 'whisper:' /var/ossec/logs/integrations.log 2>/dev/null | tail -12" \
		|| echo "no whisper log lines yet — is the connector installed (make dev-whisper-install)?"
	@echo "--- expected: invoke line for 185.220.101.1 (+auth error if the key is a placeholder);"
	@echo "---           skip reason=non-global for 10.0.0.5 and 203.0.113.45"

# The 5-minute demo (acceptance §7). Injects ONE IOC via the manager's analysisd queue and shows
# the connector's evidence. Default seed is a graph-listed Tor exit (NOT 203.0.113.45 — that is
# TEST-NET-3, which the connector's public-IP guard deliberately skips). Override with IOC=<value>.
IOC ?= 185.220.101.1

dev-demo-enrich: ## Inject one IOC (IOC=<value>, default a graph-listed Tor IP) and show the enrichment
	@$(COMPOSE_BASE) exec -T wazuh.manager sh -c "grep -q 'integrator.debug' /var/ossec/etc/local_internal_options.conf 2>/dev/null || { echo 'integrator.debug=2' >> /var/ossec/etc/local_internal_options.conf; /var/ossec/bin/wazuh-control restart >/dev/null 2>&1; sleep 5; }"
	@echo "--- injecting IOC=$(IOC) via the manager analysisd queue ---"
	@$(COMPOSE_BASE) exec -T wazuh.manager /var/ossec/framework/python/bin/python3 -c "\
	import socket,time; \
	s=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM); s.connect('/var/ossec/queue/sockets/queue'); \
	s.send(('1:whisper-demo:'+time.strftime('%b %e %H:%M:%S')+' host sshd[9]: Failed password for invalid user demo from $(IOC) port 4444 ssh2').encode()); s.close()"
	@sleep 8
	@echo "--- connector log evidence (integrations.log) ---"
	@$(COMPOSE_BASE) exec -T wazuh.manager sh -c "grep 'whisper:' /var/ossec/logs/integrations.log 2>/dev/null | tail -6" \
		|| echo "no whisper log lines — is the connector installed (make dev-whisper-install) with a real key in /var/ossec/etc/whisper.key?"
	@echo "--- the enrichment lands as a NEW alert (data.whisper.*) in wazuh-alerts-*."
	@echo "--- walkthrough with a real captured response: docs/scenarios/01-tor-ip-enrichment.md ---"

dev-acceptance: ## Run the e2e acceptance suite (TC-01..TC-22) against the live stack (needs a real key)
	python3 tests/e2e/run_acceptance.py $(TC)

# --- Whisper agent-activity log source (keyed tier) --------------------------------------
dev-logs-install: ## Install the whisper.online agent-activity log source into the dev manager
	$(COMPOSE_BASE) exec -T wazuh.manager mkdir -p $(WHISPER_SRC)
	docker cp integrations/whisper/. $$($(COMPOSE_BASE) ps -q wazuh.manager):$(WHISPER_SRC)/
	$(COMPOSE_BASE) exec -T wazuh.manager sh $(WHISPER_SRC)/install.sh --dev --group sshd --refresh-index --logs
	@echo "Installed the log source. Put the tenant API key in /var/ossec/etc/whisper.key (or set"
	@echo "WHISPER_API_KEY in the manager env) — op:logs is the KEYED tier and needs it to authenticate."

dev-logs-smoke: ## Run the log-source poller once and show the spool + decoded alert evidence
	@echo "--- running the whisper-logs poller once ---"
	@$(COMPOSE_BASE) exec -T wazuh.manager /var/ossec/integrations/whisper-logs || true
	@sleep 6
	@echo "--- spool tail (/var/ossec/logs/whisper-agent-activity.json) ---"
	@$(COMPOSE_BASE) exec -T wazuh.manager sh -c "tail -3 /var/ossec/logs/whisper-agent-activity.json 2>/dev/null" \
		|| echo "no spool yet — is the key set + activity present for this tenant?"
	@echo "--- poller log tail (/var/ossec/logs/whisper-logs.log) ---"
	@$(COMPOSE_BASE) exec -T wazuh.manager sh -c "tail -4 /var/ossec/logs/whisper-logs.log 2>/dev/null" || true
	@echo "--- decoded alerts (data.whisper_agent.*) ---"
	@$(COMPOSE_BASE) exec -T wazuh.manager sh -c "grep -o 'whisper_agent[^,]*' /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -6" \
		|| echo "no whisper_agent alerts yet — allow ~1 min for logcollector to tail the spool."

# --- Wazuh 5.0 assessment stack (dev/wazuh-5-single-node/) -------------------------------
# A separate, pinned 5.0 rc2 stack used to assess compatibility (docs/wazuh-5.md). It shares
# host ports with the 4.14.5 stack: run `make dev-down` first, never both at once.
STACK5_DIR     := dev/wazuh-5-single-node
COMPOSE5       := docker compose -f $(STACK5_DIR)/docker-compose.yml
# The spike overlays (issue #67): an enrolled agent and the finding enricher. Every overlay is
# listed for down/reset so those services stop with the stack.
COMPOSE5_AGENT := $(COMPOSE5) -f $(STACK5_DIR)/docker-compose.agent.yml
COMPOSE5_SPIKE := $(COMPOSE5_AGENT) -f $(STACK5_DIR)/docker-compose.spike.yml
WHISPER_SRC5   := /tmp/whisper-src
# Pre-release cert tool (Wazuh staging host). The SHA-256 is pinned beside the URL and checked
# before anything runs; a new rc or GA needs a new, reviewed pin.
WAZUH5_CERTS_TOOL_URL    := https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/installation-assistant/wazuh-certs-tool-5.0.0-rc2.sh
WAZUH5_CERTS_TOOL_SHA256 := b75bc38b49ee81e266c3cd5928e45a30fa7cb70a133f7b368d16fbba50bec2f4
WAZUH5_IMAGE   := wazuh/wazuh-manager:5.0.0-rc2
# The tool and the helpers run only in a throwaway container with no network, on every platform:
# no sudo, nothing executes on the host. The checksum is verified first, inside the same container.
RUN5_TOOL      := docker run --rm --network none --entrypoint bash -v "$$PWD":/work -w /work $(WAZUH5_IMAGE) -c

dev5-certs: ## 5.0 rc2: fetch the SHA-pinned cert tool, issue certs and credentials in a throwaway container (gitignored)
	@if test -f $(STACK5_DIR)/config/root-ca/certs/root-ca.pem || test -d $(STACK5_DIR)/wazuh-certificates; then \
		echo "5.0 certs already present (delete config/ wazuh-ca/ wazuh-certificates/ in $(STACK5_DIR) to regenerate)"; \
	else \
		set -e; cd $(STACK5_DIR); \
		curl -fsS -o wazuh-certs-tool.sh $(WAZUH5_CERTS_TOOL_URL); \
		cp certs-config.yml config.yml; \
		$(RUN5_TOOL) 'echo "$(WAZUH5_CERTS_TOOL_SHA256)  wazuh-certs-tool.sh" | sha256sum -c - && bash tools/utils/deployment/certificates-conf.sh --cert --copy --priv'; \
		$(RUN5_TOOL) 'bash tools/utils/deployment/credentials-conf.sh'; \
	fi

dev5-up: ## 5.0 rc2: start the stack (stop the 4.14.5 stack first)
	$(COMPOSE5) up -d

dev5-down: ## 5.0 rc2: stop the stack, agent and enricher included (keep data volumes)
	$(COMPOSE5_SPIKE) --profile setup down

dev5-reset: ## 5.0 rc2: stop the stack, agent and enricher included, and delete their data volumes
	$(COMPOSE5_SPIKE) --profile setup down -v

dev5-ps: ## 5.0 rc2: show stack status
	$(COMPOSE5) ps

dev5-whisper-install: ## 5.0 rc2: run the unchanged install.sh against the manager (expected to fail, see docs/wazuh-5.md)
	$(COMPOSE5) exec -T wazuh.manager mkdir -p $(WHISPER_SRC5)
	docker cp integrations/whisper/. $$($(COMPOSE5) ps -q wazuh.manager):$(WHISPER_SRC5)/
	$(COMPOSE5) exec -T wazuh.manager sh $(WHISPER_SRC5)/install.sh --dev --group sshd

# --- Wazuh 5.0 option (b) spike (issue #67; docs/wazuh-5.md, dev/README.md) ---------------
# An rc2 agent produces a finding, and a poller on the indexer API enriches it without the
# <integration> hook. Dev-only: nothing here ships. The enrollment token is a credential: it is
# minted on the manager API and passed to `docker compose up` through the environment of that one
# recipe shell, never echoed, put on a command line or written to the repo (Docker keeps it in the
# agent container's config until dev5-agent-down; it is single-use and expires after 600 s, and the
# API takes that lifetime as a string, not a number). The API credential goes
# to curl through its stdin config (-K -), never argv. The manager's remoted certificate names
# 127.0.0.1 and wazuh.manager, so the token is minted for the latter (the compose network name).
S5_CA          := $(STACK5_DIR)/config/root-ca/certs/root-ca.pem
S5_CREDS       := $(STACK5_DIR)/config/credentials
S5_API         := https://wazuh.manager:55000
S5_CURL        := curl -sS --resolve wazuh.manager:55000:127.0.0.1 --cacert $(S5_CA)

dev5-agent-up: ## 5.0 rc2: mint an enrollment token on the manager API and start the enrolled agent
	@set -e; \
	pw=$$(grep '^WAZUH_MANAGER_API_PASSWORD=' $(S5_CREDS)/manager.env | cut -d= -f2-); \
	pwq=$$(printf '%s' "$$pw" | sed -e 's/[\\"]/\\&/g'); \
	jwt=$$(printf 'user = "wazuh:%s"\n' "$$pwq" | $(S5_CURL) -K - -X POST "$(S5_API)/security/user/authenticate?raw=true"); \
	resp=$$(printf 'header = "Authorization: Bearer %s"\n' "$$jwt" | $(S5_CURL) -K - -X POST $(S5_API)/agents/enrollment-tokens \
		-H 'Content-Type: application/json' -d '{"address": "wazuh.manager", "embed_ca": true, "max_uses": 1, "ttl": "600s"}'); \
	tok=$$(printf '%s' "$$resp" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p'); \
	if test -z "$$tok"; then echo "dev5-agent-up: no enrollment token minted (response not shown: it may hold a credential)"; exit 1; fi; \
	WAZUH_ENROLLMENT_TOKEN="$$tok" $(COMPOSE5_AGENT) up -d wazuh.agent; \
	echo "agent started; the enrollment token went through the environment only"

dev5-agent-down: ## 5.0 rc2: remove the agent container (its identity volume stays; dev5-reset deletes it)
	$(COMPOSE5_AGENT) rm -sf wazuh.agent

IOC ?= 185.220.101.1
# A lone "Failed password" line is only an event on rc2; no stock rule turns it into a finding. The
# stock rule "SSH connection closed before authentication" fires on a pre-auth close that names a peer.
dev5-agent-demo: ## 5.0 rc2: append an sshd pre-auth close line for IOC (default 185.220.101.1) to the agent's tailed log
	@printf '%s' '$(IOC)' | grep -Eq '^[0-9A-Fa-f.:]+$$' || { echo 'IOC must be an IP address'; exit 1; }
	@$(COMPOSE5_AGENT) exec -T wazuh.agent sh -c \
		'echo "$$(date "+%b %e %H:%M:%S") whisper-spike-agent sshd[1235]: Connection closed by invalid user admin $(IOC) port 4444 [preauth]" >> /var/ossec/logs/active-responses.log'
	@echo "Appended an sshd pre-auth close from $(IOC). The finding reaches wazuh-findings-v5-* after the detector runs (about 2 minutes)."

dev5-spike-setup: ## 5.0 rc2 spike: create the enrichment template, index, least-privilege role and user (admin credential)
	mkdir -p $(STACK5_DIR)/config/whisper-enricher
	$(COMPOSE5_SPIKE) run --rm whisper.enricher-setup

dev5-spike-up: ## 5.0 rc2 spike: start the finding enricher (polls wazuh-findings-v5-*, no <integration> hook)
	$(COMPOSE5_SPIKE) up -d whisper.enricher

FINDING ?=
dev5-spike-query: ## 5.0 rc2 spike: print the enrichment stored for a finding (make dev5-spike-query FINDING=<_id>)
	@test -n "$(FINDING)" || { echo "usage: make dev5-spike-query FINDING=<finding _id>"; exit 2; }
	@$(COMPOSE5_SPIKE) run --rm --no-deps whisper.enricher query "$(FINDING)"
