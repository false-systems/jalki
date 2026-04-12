# jälki conformance specs

Target: jälki daemon + CLI at `./target/release/jalki`

These specs validate observable behavior, not implementation.
Each requirement is a testable statement about what the system does.

## Probe type: CLI

All specs probe via `jalki` CLI commands. The daemon must be running:
```
sudo ./target/release/jalki --emit stdout --cluster test
```

## Probe type: Python SDK

SDK specs probe via the Python SDK. Install first:
```
cd jalki-sdk-python && .venv/bin/pip install -e .
```
