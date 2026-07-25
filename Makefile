PYTHON := .venv/bin/python
MODEL ?= gemma4:e4b-it-qat

.PHONY: setup model serve-offline health run cli test smoke eval

setup:
	python3 -m venv .venv
	$(PYTHON) -m pip install -r requirements.txt

model:
	ollama pull $(MODEL)

serve-offline:
	OLLAMA_NO_CLOUD=1 ollama serve

health:
	GEMMA_MODEL=$(MODEL) $(PYTHON) app.py --health

run:
	GEMMA_MODEL=$(MODEL) $(PYTHON) app.py

cli:
	GEMMA_MODEL=$(MODEL) $(PYTHON) app.py --file samples/injection_phishing.txt

test:
	$(PYTHON) -m unittest discover -v

smoke:
	$(PYTHON) eval.py --mock

eval:
	GEMMA_MODEL=$(MODEL) $(PYTHON) eval.py
