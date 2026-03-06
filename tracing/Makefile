COMPOSE = docker compose -f $(dir $(abspath $(lastword $(MAKEFILE_LIST))))docker-compose.yml

.PHONY: up down restart reload logs ps

## Start all containers in the background
up:
	$(COMPOSE) up -d

## Stop and remove all containers
down:
	$(COMPOSE) down

## Restart a specific service (e.g. make restart svc=tempo) or all services
restart:
	$(COMPOSE) restart $(svc)

## Reload Grafana dashboard provisioning without restarting containers
reload:
	curl -s --user admin:admin -X POST http://localhost:3000/api/admin/provisioning/dashboards/reload

## Follow logs (optionally filtered: make logs svc=tempo)
logs:
	$(COMPOSE) logs -f $(svc)

## Show running container status
ps:
	$(COMPOSE) ps
