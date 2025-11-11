# First Contact Protocol - Secure TLS Communication

A peer-to-peer secure communication system using mutual TLS authentication with a Certificate Authority (PKI) model.

## Overview

This project implements a secure communication protocol that allows two users to:
- Discover each other on the network
- Authenticate each other using X.509 certificates
- Establish an encrypted TLS channel
- Exchange messages securely

## Quick Start

### Step 1: Setup Environment and Generate Certificates

Use the Python setup script (no Make required—works on Windows, Linux, macOS):

```powershell
# Full setup: create venv, install deps, init CA, generate certs
python setup.py all

# Or do it in steps:
python setup.py init      # Create venv, install deps, init CA
python setup.py keygen    # Generate certs for default users
```

This will:
- Create a Python virtual environment (`.venv`)
- Install required dependencies
- Initialize the Certificate Authority (CA)
- Generate certificates for `Pilot-Alpha` and `Control-Bravo`

### Step 2: Run the Clients
*** Begin README
# First Contact Protocol — Secure TLS Chat (mutual TLS)

A lightweight peer-to-peer chat demo that uses mutual TLS (mTLS) and a local
Certificate Authority (CA) for peer authentication. This repo includes tools
for issuing short-lived certificates, revoking certificates (signed JSON
CRL), and recording issued certs in a minimal Merkle transparency log.

This README covers setup, common workflows, troubleshooting, and developer
notes.

Prerequisites
- Python 3.8+ (3.10/3.11 recommended)

Quick summary
- Create a local CA and user certs, start two clients, and use `connect`/
  `send` to chat over TLS.
- Use `setup.py` for cross-platform setup (recommended). `ca_tool.py` exposes
  lower-level CA operations (issue/renew/revoke/crl).

Table of contents
- Quick start
- Commands reference
- CRL / renewal / Merkle log
- Testing
- Troubleshooting
- Developer notes

## Quick start (one line)

```powershell
# setup (venv, deps, CA, keys) and run two clients in separate terminals
python setup.py all

# Terminal 1 (server/listener)
python setup.py run --user Control-Bravo --port 7000

# Terminal 2 (initiator)
python setup.py run --user Pilot-Alpha --port 7001
connect 127.0.0.1 7000
send Hello from Pilot-Alpha!
```

## Commands reference

High-level Python setup script (preferred):

```text
python setup.py all                    # Full setup (venv + deps + CA + keys)
python setup.py init                   # Create venv and install deps, init CA
python setup.py keygen [--users ...]   # Generate keys & certs (defaults: Pilot-Alpha, Control-Bravo)
python setup.py run --user <name> --port <port>  # Run a client CLI (listen & connect)
python setup.py test                   # Run test suite
python setup.py clean                  # Remove generated files and venv
```

Lower-level CA tool (for operations you might script):

```text
python ca_tool.py init                 # Initialize root CA
python ca_tool.py genkeys <username>   # Generate RSA keypair for username
python ca_tool.py issue <username>     # Issue cert for username (CERT_VALID_DAYS env supported)
python ca_tool.py renew <username>     # Renew cert (RENEW_VALID_DAYS env)
python ca_tool.py revoke <username>    # Revoke certificate and sign CRL
python ca_tool.py crl                  # Print CRL summary
```

Environment variables (optional):

```powershell
$env:CERT_VALID_DAYS='7'      # Issue certs valid N days (default 30)
$env:RENEW_VALID_DAYS='7'     # Renewed cert lifetime (default 7)
```

## Certificate lifecycle: issue, renew, revoke

- Issue: `ca_tool.py issue <user>` or `setup.py keygen`
- Renew: `ca_tool.py renew <user>` (short-lived certs reduce CRL size)
- Revoke: `ca_tool.py revoke <user>` — adds the cert serial to `ca/crl.json`

Files created/used:
- `ca/root_cert.pem`, `ca/root_key.pem` — CA materials
- `ca/crl.json`, `ca/crl.sig` — signed JSON CRL and signature
- `ca/merkle_log.json` — transparency log with leaf hashes + root
- `keys/<USER>_key.pem`, `keys/<USER>_cert.pem` — user key/cert

Revocation policy & behavior
- Certificate validation (in `certificate_validation.py`) verifies:
  1. Certificate signature against the CA
  2. Validity window (UTC-aware)
  3. CRL signature (if `ca/crl.json` exists) and whether the serial is revoked

If the CRL is present but its signature cannot be verified, validation fails (fail-closed).

## Running the clients (chat example)

Terminal 1 (Control-Bravo):

```powershell
python setup.py run --user Control-Bravo --port 7000
```

Terminal 2 (Pilot-Alpha):

```powershell
python setup.py run --user Pilot-Alpha --port 7001
connect 127.0.0.1 7000
send Hello!
```

Commands inside the CLI:
- `connect <IP> <PORT>` — initiate connection to a peer
- `send <MSG>` — send an encrypted message over the established TLS channel
- `status` — show connection state
- `disconnect` — close the current connection

## Transparency log (Merkle)

`merkle_log.py` records SHA-256 hashes of all issued certificates into
`ca/merkle_log.json` and computes a Merkle root. This gives basic auditability
of what the CA issued; the module can be extended later to produce inclusion
proofs if needed.

## Testing

Run the project's pytest suite:

```powershell
pytest -q
```

Tests create ephemeral CAs and certificates and temporarily point `app.utils`
paths to those files so tests are hermetic. Existing tests cover handshake,
channel integrity, I/O robustness, forward secrecy, and handshake attack cases.

Optional local verification script

If you want a quick smoke-check outside of the test suite, there's a small
helper script, `verify.py`, at the repository root. It performs a handful of
convenience checks (files exist, Merkle log structure, CRL presence/signature)
and prints a short summary. This is handy during manual testing but is not a
replacement for the automated pytest suite.

Usage:

```powershell
python verify.py
```

If you prefer CI-covered checks, I can convert the same checks into a pytest
test and remove the top-level script — let me know which you prefer.

## Troubleshooting

- Handshake or certificate verification failures:
  - Ensure `ca/root_cert.pem` is being used by both peers (check `app/utils.py` paths).
  - If you changed CA key algorithm (e.g., to Ed25519), ensure CRL signing/verification code is compatible.

- Common error: "Missing Authority Key Identifier" or "CA cert does not include key usage extension"
  - Recreate the CA with `python ca_tool.py init` (or `python setup.py init`) which uses `build_ca.py` to include the proper extensions (KeyUsage, SKI, AKI).

- CRL and revocation tests:
  - Revoke a cert: `python ca_tool.py revoke <username>` — this updates `ca/crl.json` and creates `ca/crl.sig`.
  - Validation will reject revoked certs on connect (handshake closes and prints an error).

- If `setup.py init` fails to install pip in the venv, run:

```powershell
python -m ensurepip --upgrade
```

## Developer notes

- `app/handshake.py` performs application-level certificate validation after the TLS handshake to enforce CRL checks; the socket is closed if validation fails.
- `certificate_validation.py` performs signature verification and checks validity windows using timezone-aware datetimes to avoid deprecation warnings.
- The repository includes helper modules `crl.py` and `merkle_log.py` for CRL and transparency log management respectively.
