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
        dev-whisper-install dev-whisper-uninstall dev-whisper-smoke \
        dev-logs-install dev-logs-smoke

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