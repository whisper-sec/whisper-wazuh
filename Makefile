# whisper-wazuh — developer convenience targets.
# Wraps the local single-node Wazuh dev stack under dev/wazuh-single-node/.

SHELL := /usr/bin/env bash

STACK_DIR    := dev/wazuh-single-node
CERT_DIR     := $(STACK_DIR)/config/certs
COMPOSE      := docker compose -f $(STACK_DIR)/docker-compose.yml -f $(STACK_DIR)/docker-compose.traefik.yml
COMPOSE_BASE := docker compose -f $(STACK_DIR)/docker-compose.yml

.DEFAULT_GOAL := help

.PHONY: help dev-init dev-certs dev-up dev-up-basic dev-down dev-reset dev-restart dev-ps dev-logs

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

dev-down: ## Stop the stack (keep data volumes)
	$(COMPOSE) down

dev-reset: ## Stop the stack and wipe all data volumes
	$(COMPOSE) down -v

dev-restart: ## Restart the stack
	$(COMPOSE) restart

dev-ps: ## Show stack status
	$(COMPOSE) ps

dev-logs: ## Follow stack logs
	$(COMPOSE) logs -f