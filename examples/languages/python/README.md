# Python (pip, uv, Poetry, Pipenv; gunicorn, uvicorn, Celery)

Deploy with git and create the virtual environment from a lockfile that pins hashes: `uv sync --frozen`, `poetry install --sync`, `pipenv install --deploy`, or `pip install --require-hashes -r requirements.txt`. The virtual environment is found in the service root (`.venv`, `venv`, `env`); list others under `installs`.

Checked: every installed file against the wheel from PyPI named by the lockfile hash (via each wheel's `RECORD`), entry-point scripts against the installer's template, `pyvenv.cfg` and the interpreter link, uv's `_virtualenv` hook against uv's source, and each process for `PYTHONPATH`, `PYTHONSTARTUP`, `PYTHONBREAKPOINT`, `-c`, and `-X pycache_prefix=` (bytecode read from elsewhere).

Bytecode (`__pycache__`) cannot be compared with a wheel; it is reported by `policy.bytecode`. Setting `PYTHONDONTWRITEBYTECODE=1` for the service, or compiling nothing on the server, avoids it.

Configuration: [attester.yml](attester.yml) on each server, [auditstatus.config.yml](auditstatus.config.yml) for the verifier.
