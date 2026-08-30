PYTHON ?= python3

.PHONY: test quality package check

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover -s tests -v

quality:
	PYTHONPATH=src $(PYTHON) scripts/quality_gate.py

package:
	PIP_CACHE_DIR=/tmp/secure-agent-gateway-pip-cache $(PYTHON) -m pip wheel . --no-deps --no-build-isolation --wheel-dir /tmp/secure-agent-gateway-wheel

check: test quality package
