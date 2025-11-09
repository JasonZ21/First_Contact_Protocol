# --- Makefile for First Contact Protocol ---

# Configuration Variables
PYTHON := .venv/bin/python3
CLIENT_MODULE := app.cli
CA_TOOL := ca_tool.py
CONTROL_PORT := 7000
PILOT_PORT := 7001

# Default Users (Used if CUSTOM_USERS is NOT specified on the command line)
PILOT_USER := Pilot-Alpha
CONTROL_USER := Control-Bravo
CA_USERS := $(PILOT_USER) $(CONTROL_USER)

PROJECT_ROOT := $(shell pwd)
DEPENDENCIES := cryptography pynacl cbor2

.PHONY: all setup keys run run-all clean

all: setup keys

# ----------------- ENVIRONMENT SETUP -----------------

setup: .venv
	@echo "--- Installing Dependencies ---"
	@source .venv/bin/activate; pip install $(DEPENDENCIES)

.venv:
	@echo "--- Creating Virtual Environment (.venv) ---"
	@python3 -m venv .venv

# ----------------- CRYPTOGRAPHIC SETUP -----------------

# Usage: make keys [CUSTOM_USERS="User1 User2"]
keys: setup
	@echo "--- Generating and Issuing Certificates ---"
	@source .venv/bin/activate && \
	    rm -rf ca keys && \
	    echo "Initializing Root CA..." && \
	    $(PYTHON) $(CA_TOOL) init && \
	    \
	    echo "Generating keys and issuing certs..." && \
	    \
	    USER_LIST='$(if $(CUSTOM_USERS),$(CUSTOM_USERS),$(CA_USERS))' && \
	    \
	    for user in $$USER_LIST; do \
	        echo "   -> Processing user: $$user"; \
	        $(PYTHON) $(CA_TOOL) genkeys $$user; \
	        $(PYTHON) $(CA_TOOL) issue $$user; \
	    done && \
	    echo "Key Generation Complete."
# ----------------- EXECUTION -----------------

# Target to run a single client (Control or Pilot)
# Usage: make run USER=Pilot-Alpha PORT=7001
run:
	@echo "--- Running Single Client: $(USER) on Port $(PORT) ---"
	@source .venv/bin/activate && \
	    export USER_ID=$(USER) && \
	    export LISTEN_TCP_PORT=$(PORT) && \
	    $(PYTHON) -m $(CLIENT_MODULE)

# ----------------- CLEANUP -----------------

clean:
	@echo "--- Cleaning Up Generated Files ---"
	rm -rf .venv
	rm -rf ca keys
	rm -rf __pycache__