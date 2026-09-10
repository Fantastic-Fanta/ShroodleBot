.PHONY: verify

PY := $(shell test -x ENV/bin/python && echo ENV/bin/python || echo python3)

verify:
	$(PY) -m compileall -q -f .
	PYTHONPATH=. $(PY) -c "import auth, bot, config, formatter, job_store, runner"
	PYTHONPATH=. $(PY) -c "import commands.pentest, commands.status, commands.cancel"
