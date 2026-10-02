.PHONY: up down logs transform airflow test reset

up:            ## Start Kafka, producer, Spark streaming and dashboard
	@test -f .env || cp .env.example .env
	docker compose up -d --build

down:
	docker compose --profile tools --profile orchestration down

logs:
	docker compose logs -f spark producer

transform:     ## Run dbt models + tests against the lakehouse
	docker compose run --rm dbt

airflow:       ## Start Airflow (login credentials are printed in the logs)
	docker compose --profile orchestration up -d airflow

test:          ## Unit tests (no Docker needed)
	pytest -q

reset:         ## Delete all lake data and checkpoints
	docker compose --profile tools --profile orchestration down -v
