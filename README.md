# First Contact Protocol - Secure TLS Communication

A peer-to-peer secure communication system using mutual TLS authentication with a Certificate Authority (PKI) model.

## Overview

This project implements a secure communication protocol that allows two users to:
- Discover each other on the network
- Authenticate each other using X.509 certificates
- Establish an encrypted TLS channel
- Exchange messages securely

## Requirements
- Python 3.7 or higher
- Make (build automation tool)

Install dependencies (if you haven't already):

```powershell
python -m pip install -r requirements.txt
```

## Quick Start

### Step 1: Setup Environment and Generate Certificates

```bash
make setup keys
```

This will:
- Create a Python virtual environment
- Install required dependencies
- Initialize the Certificate Authority (CA)
- Generate certificates for `Pilot-Alpha` and `Control-Bravo`

### Step 2: Run the Clients

**Terminal 1 - Control-Bravo:**
```bash
make run USER=Control-Bravo PORT=7000
```

**Terminal 2 - Pilot-Alpha:**
```bash
make run USER=Pilot-Alpha PORT=7001
```

### Step 3: Connect and Chat

In Pilot-Alpha's terminal:
```
> connect 127.0.0.1 7000
Attempting secure connection to 127.0.0.1:7000...
[SUCCESS] TLS established. Peer ID: Control-Bravo

> send Hello from Pilot!
[Me] > Hello from Pilot!
```

In Control-Bravo's terminal (you'll see):
```
[Pilot-Alpha] > Hello from Pilot!

> send Hello from Control!
[Me] > Hello from Control!
```

## Available Commands

### Makefile Commands

```bash
make setup          # Create virtual environment and install dependencies
make keys           # Generate CA and user certificates
make run            # Run a single client (requires USER and PORT)
make clean          # Remove all generated files and virtual environment
```

### Custom Users

To generate certificates for different users:
```bash
make keys CUSTOM_USERS="Alice Bob"
```

## Clean Up

Remove all generated files:
```bash
make clean
```

## Tests

This repository includes a pytest-based test suite that exercises the current
TLS-based `app` API (handshake and channel code). The tests run entirely
locally and generate ephemeral Certificate Authority (CA) and identity
certificates for deterministic, isolated test runs.

Key points:

- Tests use a `session_pair` fixture (in `tests/conftest.py`) which:
	- Creates a temporary CA and two identity cert/key pairs.
	- Writes PEM files to a temporary directory.
	- Temporarily points `app.utils` certificate path constants at those PEM
		files so the handshake code loads the test certificates.
	- Spins up an in-process TLS server and client and yields two
		`SessionState` objects containing the negotiated `ssl.SSLSocket` as
		`.conn`.

- Helpers live in `tests/utils/`:
	- `ca.py` — creates test root CA and issues leaf identity certificates.
	- `transport.py` — simple in-memory/intercepting transports used by some
		legacy tests.
	- `timewrap.py` — small context manager placeholder used by tests.

What the tests cover (TLS-focused equivalents):

- Channel integrity: basic client->server TLS send/receive roundtrip.
- IO robustness: recv loop handling abrupt remote close, and large message
	handling across multiple TLS records.
- Forward secrecy: verifies the negotiated cipher suite provides ephemeral
	key exchange (accepts TLS 1.3 or ECDHE/DHE suites).
- Handshake MITM: ensures a client rejects a server cert signed by an
	untrusted (attacker) CA.
- Replay/truncation: tests that replaying recorded server bytes or a server
	truncating a payload does not result in a valid handshake or silent data
	corruption.

How to run the tests (PowerShell)

Run the full test suite:

```powershell
pytest -q
```

Run a single test (example):

```powershell
pytest tests/test_channel_integrity.py::test_tls_send_receive_roundtrip -q
```
