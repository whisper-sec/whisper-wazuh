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
        dev-agent-up dev-agent-down dev-agent-logs dev-agent-demo

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