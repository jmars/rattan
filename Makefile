PY := .venv/bin/python
PYTHONPATH := src
export PYTHONPATH

.PHONY: all submodule core test lint

all:
	@echo "rattan MCP server targets:"
	@echo "  make submodule       - init the palisade submodule (vendor/palisade)"
	@echo "  make core            - build the palisade core (stage3 + probes)"
	@echo "  make test            - build core then run the MCP tests"
	@echo "  make lint            - syntax-check src and tests"

submodule:
	git submodule update --init

core:
	make -C vendor/palisade stage3 probes

test: core
	$(PY) -m unittest discover -s tests -v

lint:
	$(PY) -m compileall -q src tests && echo "syntax OK"
