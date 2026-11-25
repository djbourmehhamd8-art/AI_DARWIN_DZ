.PHONY: help test check fuzz lint run zip release clean
PY ?= python3

help:            ## list the targets
	@grep -E '^[a-z]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

test:            ## unit + integration tests
	$(PY) -m unittest discover -s tests -t .

fuzz:            ## hostile-input robustness run (add ARGS=--quick for the CI smoke run)
	$(PY) scripts/fuzz.py $(ARGS)

lint:            ## ruff (real bugs only; config in pyproject.toml)
	$(PY) -m ruff check bot main.py scripts tests

check:           ## everything CI runs: compile, shell syntax, tests, quick fuzz
	$(PY) -m compileall -q bot main.py tests scripts
	for f in deploy/*.sh install_termux.sh start.sh stop.sh; do bash -n "$$f"; done
	$(MAKE) test
	$(MAKE) fuzz ARGS=--quick

run:             ## start the bot (reads .env)
	$(PY) main.py

release:         ## build a clean, checksummed source release
	$(PY) scripts/build_release.py

zip: release

clean:           ## remove caches
	find . -name __pycache__ -prune -exec rm -rf {} +
