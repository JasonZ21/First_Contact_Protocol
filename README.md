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
- Dependencies (installed automatically): `cryptography`, `pynacl`, `cbor2`

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