COMPOSE_CMD	:= docker compose -p astra-vanguard
COMPOSE_YML := ./deploy/compose.yml

.PHONY: up down

up:
	$(COMPOSE_CMD) -f $(COMPOSE_YML) up --build --detach --remove-orphans

down:
	$(COMPOSE_CMD) -f $(COMPOSE_YML) down --remove-orphans
