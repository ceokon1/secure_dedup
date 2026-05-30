up:
	docker compose up --build

down:
	docker compose down -v

migrate:
	alembic upgrade head

test:
	pytest -q

api:
	uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

worker-once:
	python -m worker.main --once
