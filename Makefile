PYTHON ?= python3
VENV ?= .venv
VENV_PYTHON := $(VENV)/bin/python
DEMO_SUMMARY ?= .sentinel/make-demo-summary.json
DEMO_MEMORY_DB ?= .sentinel/demo-memory.sqlite

.PHONY: init doctor demo prod

init:
	$(PYTHON) scripts/init_sentinel.py --env-file .env --venv $(VENV)

doctor:
	$(VENV_PYTHON) scripts/doctor.py --env-file .env --venv $(VENV)

demo:
	$(VENV_PYTHON) scripts/run_sentinel_demo.py --memory-db $(DEMO_MEMORY_DB) --summary-output $(DEMO_SUMMARY)
	$(VENV_PYTHON) scripts/assert_demo_summary.py $(DEMO_SUMMARY)

prod:
	docker compose --env-file .env up --build
