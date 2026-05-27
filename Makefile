PYTHON ?= python3

demo:
	./scripts/demo.sh

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check capfence tests examples

typecheck:
	$(PYTHON) -m mypy capfence

build:
	rm -rf dist build
	$(PYTHON) -m build
	$(PYTHON) -m twine check dist/*

docs:
	$(PYTHON) -m mkdocs build --strict

release-check: test lint typecheck build docs

clean:
	rm -rf dist build site .pytest_cache .ruff_cache .mypy_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +
	find . -name '.DS_Store' -type f -delete

.PHONY: demo test lint typecheck build docs release-check clean
