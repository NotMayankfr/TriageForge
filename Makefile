.PHONY: help install up down restart ps test diagnose diagnose-tls break fix list-faults clean

SHELL := /bin/bash
FAULT ?= 02_gunicorn_down
URL ?= http://localhost:80

help:
	@echo "=========================================================================="
	@echo "TriageForge: Deterministic Cloud Failure Triage Lab"
	@echo "=========================================================================="
	@echo "Management targets:"
	@echo "  make install        Install triageforge CLI and dev dependencies"
	@echo "  make up             Start the local Docker Compose stack"
	@echo "  make down           Stop and remove the local Docker Compose stack"
	@echo "  make restart        Restart the stack containers"
	@echo "  make ps             List status of stack containers"
	@echo ""
	@echo "Diagnostic targets:"
	@echo "  make diagnose       Run bottom-up diagnostic probe against \$$URL"
	@echo "  make diagnose-tls   Run bottom-up diagnostic probe against HTTPS (:443)"
	@echo "  make test           Execute full pytest unit and harness test suite"
	@echo ""
	@echo "Fault injection targets:"
	@echo "  make list-faults    Display all 10 realistic failure catalog scenarios"
	@echo "  make break FAULT=x  Inject failure scenario 'x' and run triage probe"
	@echo "  make fix FAULT=x    Recover from failure scenario 'x' and verify health"
	@echo "=========================================================================="

install:
	pip install -e ".[dev]"

up:
	docker compose -f stack/docker-compose.yml up -d --build
	@echo "Waiting for stack healthcheck..."
	@sleep 3
	@curl -sf http://localhost:80/health >/dev/null && echo "Stack is UP and healthy on port 80 & 443" || echo "Starting up..."

down:
	docker compose -f stack/docker-compose.yml down -v

restart:
	docker compose -f stack/docker-compose.yml restart

ps:
	docker compose -f stack/docker-compose.yml ps

test:
	pytest tests -v

diagnose:
	triageforge diagnose --url $(URL)

diagnose-tls:
	triageforge diagnose --url https://localhost:443

pcap:
	triageforge pcap docs/fixtures/sample_traffic.pcap

logs-vpc:
	triageforge logs --type vpc-flow docs/fixtures/sample_vpc_flow.log

logs-nginx:
	triageforge logs --type nginx docs/fixtures/sample_nginx_access.log

dojo:
	triageforge dojo start

list-faults:
	triageforge list-faults

break:
	@echo "--> Injecting fault: $(FAULT)..."
	@triageforge inject $(FAULT)
	@echo "--> Running TriageForge automated diagnosis probe..."
	@-triageforge diagnose --url $(URL)

fix:
	@echo "--> Recovering fault: $(FAULT)..."
	@triageforge recover $(FAULT)
	@echo "--> Verifying stack health..."
	@triageforge diagnose --url $(URL)

clean:
	rm -rf .pytest_cache build dist *.egg-info htmlcov .coverage incident_report.json
	find . -type d -name __pycache__ -exec rm -rf {} +
