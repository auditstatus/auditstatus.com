# Python

Deploy a git checkout and create the virtual environment from a lockfile that pins file hashes. The attester hashes every file in the checkout, every file each installed distribution's `RECORD` lists, the scripts in the environment's `bin/`, and its start-up hook, and inspects each Python process. The verifier downloads the wheel whose SHA-256 the lockfile pins, checks it, and compares its contents with what is installed, following the wheel install rules.


## What gets verified

| What                                                        | Reference                                                                                                                                                                                                                                    | Check           |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------- |
| Tracked files                                               | The deployed commit, on the audited branch                                                                                                                                                                                                   | `source`        |
| Each installed distribution in `site-packages`              | The wheel the lockfile pins by SHA-256, matched to the installed `WHEEL` tags, compared file by file through `RECORD`                                                                                                                        | `packages:pypi` |
| Entry-point scripts in `bin/`                               | The script the installer generates for the wheel's entry points                                                                                                                                                                              | `packages:pypi` |
| Other files in `bin/`                                       | Must belong to an installed distribution; activation scripts and interpreter links are listed                                                                                                                                                | `packages:pypi` |
| Files in `site-packages` no distribution claims             | None: Python runs `.pth` files and `sitecustomize` at start-up, so each one fails                                                                                                                                                            | `packages:pypi` |
| The `_virtualenv` start-up hook (uv, virtualenv)            | The hook in the source of the uv or virtualenv version `pyvenv.cfg` names                                                                                                                                                                    | `packages:pypi` |
| `pip`, `setuptools`, `wheel` seeded by the environment tool | The registry release, when the lockfile does not pin them; on Debian and Ubuntu, also the distribution's patched wheel (`python3-pip-whl`, `python3-setuptools-whl`) of that version in its signed archive, which `python3 -m venv` installs | `packages:pypi` |
| Each process                                                | `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONBREAKPOINT`, `PYTHONWARNINGS` imports, `-c`, `-X pycache_prefix=`, debuggers (`-m debugpy`, `-m pdb`), memory maps                                                                       | `process`       |


## Requirements

* Commit a lockfile with hashes. The first one found at the repository root is read, in this order: `uv.lock`, `pylock.toml`, `poetry.lock`, `Pipfile.lock`, `requirements.lock`, `requirements.txt`. A requirements file must carry `--hash=sha256:` for each package (`pip-compile --generate-hashes`, `uv export`).
* Install from the lockfile, nothing else:
  * `uv sync --frozen --no-install-project`
  * `poetry install --sync`
  * `pipenv install --deploy`
  * `pip install --require-hashes -r requirements.txt`
* Install wheels, not source distributions. A package the server built from a source distribution has no reference (`policy.unverifiablePackages`, default `fail`).
* Do not install the project itself into the environment. Its entry in the lockfile pins no hash, so it cannot be verified. Run it from the checkout instead (`--no-install-project` with uv).
* Do not install in editable or egg mode (`setup.py develop`): no file hashes are recorded.
* Keep bytecode out: install without compiling (uv's default, `pip install --no-compile`) and run with `PYTHONDONTWRITEBYTECODE=1` or `python -B`. Bytecode written while the app runs also adds `__pycache__` to the directories of its code after the process started, which fails (`policy.metadataChangedAfterStart`).
* Ignore the environment and `__pycache__/` in `.gitignore`.


## Attester configuration

```yaml
version: 2
services:
  - name: app
    root: /srv/app/current
    user: app
    ecosystems: [pypi]
```

Environments named `.venv`, `venv`, `env`, `.virtualenv` or `virtualenv` in the service root are found (each needs a `pyvenv.cfg`). For an environment elsewhere, give its `site-packages` directory:

```yaml
    installs:
      - ecosystem: pypi
        dir: /opt/venvs/app/lib/python3.12/site-packages
```

The environment's `bin/` and `pyvenv.cfg` are read from three levels above that directory.


## Verifier configuration

```yaml
version: 2
services:
  - name: app
    repository:
      url: https://github.com/example/app.git
      branch: main
    # Where the lockfile is, when not at the repository root:
    # lockfiles:
    #   pypi: backend/uv.lock
servers:
  - name: app1
    host: app1.example.com
```

Registry and source locations can be changed under `references.registries` (`pypi`, `uvSource`). See [configuration](../configuration.md).


## Build and deploy

The tested setup:

```sh
uv lock                                   # in the repository, then commit uv.lock
git clone https://github.com/example/app.git /srv/app/current
cd /srv/app/current
UV_PYTHON_DOWNLOADS=never PYTHONDONTWRITEBYTECODE=1 uv sync --frozen --no-install-project
.venv/bin/python -B main.py
```

* With pip on Debian or Ubuntu: `python3 -m venv .venv`, then `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pip install --no-compile --require-hashes -r requirements.txt`. `python3 -m venv` compiles the pip it installs; remove that bytecode once: `find .venv -name __pycache__ -prune -exec rm -r {} +`. The pip the environment starts with is the distribution's, compared with its wheel in the signed archive. The interpreter is compared with the archive too: a Python from another repository (a PPA) is not in it, and is reported as unexplained code unless listed in `executables`.
* gunicorn, uvicorn and Celery run from `.venv/bin/`; their scripts are compared with the installer's template for their entry points.
* Restart the workers after each deploy. A tracked file changed after a process started fails (`policy.modifiedAfterStart`).


## Common findings

| Finding                                                                                                                       | Cause and fix                                                                                                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `No lockfile at the deployed commit pins these packages`                                                                      | No supported lockfile at the commit. Commit one, or set `lockfiles.pypi`.                                                                                                                                                                |
| `installed package is not pinned by the lockfile`                                                                             | The environment has a package the lockfile does not list. Recreate it from the lockfile.                                                                                                                                                 |
| `the lockfile pins no hashes for this package`                                                                                | A requirements file without `--hash`, or the project itself installed into the environment.                                                                                                                                              |
| `built on the server from a source distribution`                                                                              | No wheel for the server's platform and Python version is pinned. Pick versions that publish wheels for it, and lock again.                                                                                                               |
| `files differ from the pinned wheel`                                                                                          | A file in `site-packages` was changed after install. Recreate the environment.                                                                                                                                                           |
| `Python bytecode (.pyc) cannot be verified`                                                                                   | `__pycache__` in `site-packages`. Install without compiling and run with `PYTHONDONTWRITEBYTECODE=1` (`policy.bytecode`, default `warn`). Pip writes bytecode for its own modules when it runs, so set the variable for the install too. |
| `Files in bytecode cache directories that are not bytecode`                                                                   | Something other than `.pyc` is in a `__pycache__` directory. Remove it.                                                                                                                                                                  |
| `Files in site-packages that belong to no installed package`                                                                  | A stray `.pth`, `sitecustomize.py` or leftover. Remove it.                                                                                                                                                                               |
| `Files in the environment's bin directory that no installed package created`                                                  | A script added to `bin/` by hand. Remove it.                                                                                                                                                                                             |
| `The environment's start-up hook ... differs from its creator's release`                                                      | `_virtualenv.py` or `_virtualenv.pth` was changed. Recreate the environment.                                                                                                                                                             |
| `The environment's start-up hook (_virtualenv) matches its creator's release`                                                 | Informational: the hook matches the uv or virtualenv release that created the environment.                                                                                                                                               |
| `Interpreter links and activation scripts in the environment (not run by the application)`                                    | Informational: files in `bin/` that belong to the environment, not to a package.                                                                                                                                                         |
| `Packages the environment tool installed (not in the lockfile) match the distribution's patched wheels in its signed archive` | Informational: `python3 -m venv` on Debian or Ubuntu installed the distribution's pip (or setuptools), which differs from the registry's; it matches the wheel the distribution's package of that version ships.                         |
| `PYTHONPATH` (process)                                                                                                        | The service sets `PYTHONPATH`. Remove it, or run with `-I`.                                                                                                                                                                              |


## Limits

* Bytecode caches cannot be compared with anything; they are only listed.
* Source distributions built on the server cannot be verified.
* The interpreter itself is not part of this check. It is explained as code when a distribution package owns it (compared with the signed Debian or Ubuntu archive), or when it is pinned under `executables`; see [the verifier guide](../verifier.md).
* The project's own `.py` files are compared through the git checkout, not the environment.

See [how it works](../how-it-works.md) for the overall flow.
