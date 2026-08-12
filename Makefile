PY := .venv/bin/python
PYTHONPATH ?= src

COSMCC      ?= cosmocc
ASSIMILATE  ?= assimilate
STAGE3_SRC  := src/rattan/stage3.c
PLEDGE_RATTAN_SRC := src/rattan/cosmo/pledge-rattan.c
STAGE3_BIN  := bin/stage3
PROBE_DIR   := tests/probes
CFLAGS_STAGE3 := -std=c11 -Os -Wall -Wextra -Werror -fno-stack-protector
# Relaxed flags for the vendored cosmocc pledge (its own code trips -Werror on
# unused-param / sign-compare; must not be over-strict on third-party code).
CFLAGS_STAGE3_RELAXED := -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
    -Wno-unused-function -fno-stack-protector

.PHONY: all stage3 probes bootstrap-rootfs verify test lint

all:
	@echo "rattan Makefile targets:"
	@echo "  make verify            - run the host capability probe / startup gate"
	@echo "  make test              - run the unittest suite"
	@echo "  make stage3            - build the stage3 inner binary"
	@echo "  make probes            - build the syscall probes for stage3 tests"
	@echo "  make bootstrap-rootfs  - bootstrap the Arch base rootfs (not implemented in M0)"
	@echo "  make lint              - syntax-check src and tests"

$(STAGE3_BIN): $(STAGE3_SRC) $(PLEDGE_RATTAN_SRC)
	@mkdir -p bin
	# The vendored cosmocc pledge (pledge-rattan.c) must be linked into stage3 so
	# its sys_pledge_linux/kPledge (patched to allow read-only xattr syscalls)
	# override the precompiled libc's. It needs GNU extensions and a relaxed
	# warning set (cosmocc's own code trips -Werror), so compile it separately
	# from stage3.c (which stays strict c11 + -Werror).
	$(COSMCC) -std=gnu11 $(CFLAGS_STAGE3_RELAXED) -c $(PLEDGE_RATTAN_SRC) -o bin/pledge-rattan.o
	$(COSMCC) $(CFLAGS_STAGE3) -c $(STAGE3_SRC) -o bin/stage3.o
	$(COSMCC) -o bin/stage3.ape bin/pledge-rattan.o bin/stage3.o
	$(ASSIMILATE) -f bin/stage3.ape
	mv bin/stage3.ape $(STAGE3_BIN)
	rm -f bin/pledge-rattan.o bin/stage3.o
	@file $(STAGE3_BIN) | grep -q 'ELF' || { echo "assimilate failed"; rm -f $(STAGE3_BIN); exit 1; }

stage3: $(STAGE3_BIN)

# Probe binaries:
#  - Syscall probes (keytest/ptracetest/mounttest/unsharetest) use only
#    glibc-compatible APIs and are built with the host gcc as static binaries.
#    This keeps a clean differential: the syscall is reachable standalone
#    (EINVAL/ENOENT/0) but blocked with EPERM under stage3's seccomp.
#  - reverse_order_probe calls cosmocc's pledge()/unveil(), so it must be built
#    with cosmocc and assimilated to a native ELF (a fat APE won't exec directly
#    without the APE loader).
CC        ?= gcc
SYSCALL_PROBES := keytest ptracetest mounttest unsharetest
COSMO_PROBES   := reverse_order_probe

$(PROBE_DIR)/%: $(PROBE_DIR)/%.c
	@mkdir -p $(PROBE_DIR)
	$(CC) -Os -static -o $@ $<

$(PROBE_DIR)/reverse_order_probe: $(PROBE_DIR)/reverse_order_probe.c
	@mkdir -p $(PROBE_DIR)
	$(COSMCC) -Os -o $(PROBE_DIR)/reverse_order_probe.ape $<
	$(ASSIMILATE) -f $(PROBE_DIR)/reverse_order_probe.ape
	mv $(PROBE_DIR)/reverse_order_probe.ape $@
	@file $@ | grep -q 'ELF' || { echo "assimilate failed for $@"; rm -f $@; exit 1; }

probes: $(SYSCALL_PROBES:%=$(PROBE_DIR)/%) $(PROBE_DIR)/reverse_order_probe

bootstrap-rootfs:
	bash bin/bootstrap-rootfs.sh

verify:
	bash bin/verify.sh

test: stage3 probes
	$(PY) -m unittest discover -s tests -v

lint:
	$(PY) -m compileall -q src tests && echo "syntax OK"
