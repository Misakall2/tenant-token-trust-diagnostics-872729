# Local development environment

Upstream: https://github.com/authlib/joserfc

Source commit: f345ff71cd6c36452a4e11e47b805ad450a95dd8

Windows PowerShell, Python 3.11 or later. Install in a project virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install cryptography==46.0.3 pytest==8.4.2
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
.\.venv\Scripts\python.exe -m pytest tests -q
```

The optional draft-algorithm tests require pycryptodome. Core verification does not require external services. Do not commit generated private keys, local credentials, or virtual environments.
