PY := .venv/bin/python
PYTHONPATH ?= src

.PHONY: all stage3 bootstrap-rootfs verify test lint

all:
	@echo "rattan Makefile targets:"
	@echo "  make verify            - run the host capability probe / startup gate"
	@echo "  make test              - run the unittest suite"
	@echo "  make stage3            - build the stage3 inner binary (not implemented in M0)"
	@echo "  make bootstrap-rootfs  - bootstrap the Arch base rootfs (not implemented in M0)"
	@echo "  make lint              - syntax-check src and tests"

stage3:
	@echo "stage3 build not implemented in M0"

bootstrap-rootfs:
	@echo "bootstrap-rootfs not implemented in M0"

verify:
	PYTHONPATH=$(PYTHONPATH) $(PY) -m rattan --probe

test:
	$(PY) -m unittest discover -s tests -v

lint:
	$(PY) -m compileall -q src tests && echo "syntax OK"
