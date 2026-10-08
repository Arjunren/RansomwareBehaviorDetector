PYTHON ?= python
DATASET ?= data/processed/training.csv

.PHONY: install lint format typecheck test security train evaluate serve docker-build docker-up
install:
	$(PYTHON) -m pip install -e ".[dev]"
	pre-commit install
lint:
	ruff check .
format:
	ruff format .
typecheck:
	mypy src
test:
	$(PYTHON) -m pytest -q
security:
	bandit -q -r src
	pip-audit --requirement requirements.txt
train:
	ransomware-behavior-detector train --dataset "$(DATASET)"
evaluate:
	ransomware-behavior-detector evaluate
serve:
	uvicorn ransomware_behavior_detector.api:app --host 127.0.0.1 --port 8000
docker-build:
	docker compose build
docker-up:
	docker compose up
