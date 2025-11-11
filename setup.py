#!/usr/bin/env python3
"""
Python-friendly setup script for First Contact Protocol.

Replaces Makefile functionality:
  - Create and activate virtual environment
  - Install dependencies
  - Initialize CA
  - Generate user certificates
  - Clean up generated files

Usage:
  python setup.py --help
  python setup.py init          # Setup venv, install deps, create CA
  python setup.py keygen        # Generate certs for default users (Pilot-Alpha, Control-Bravo)
  python setup.py keygen --users Alice Bob Charlie  # Custom users
  python setup.py clean         # Remove venv, ca/, keys/
  python setup.py all           # init + keygen (full setup)
"""

import os
import sys
import subprocess
import argparse
import shutil
import json
from pathlib import Path


# Project configuration
PROJECT_ROOT = Path(__file__).resolve().parent
VENV_DIR = PROJECT_ROOT / ".venv"
CA_TOOL = PROJECT_ROOT / "ca_tool.py"
PYTHON_CMD = "python" if sys.platform == "win32" else "python3"

# Venv python executable
if sys.platform == "win32":
    VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
else:
    VENV_PYTHON = VENV_DIR / "bin" / "python"

DEFAULT_USERS = ["Pilot-Alpha", "Control-Bravo"]
DEPENDENCIES = ["cryptography", "pynacl", "cbor2", "pytest"]


def print_header(msg):
    """Print a formatted header message."""
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def print_step(msg):
    """Print a step message."""
    print(f"\n[*] {msg}")


def print_success(msg):
    """Print a success message."""
    print(f"\n[✓] {msg}")


def print_error(msg):
    """Print an error message."""
    print(f"\n[✗] ERROR: {msg}", file=sys.stderr)


def run_command(cmd, description=""):
    """Run a shell command and return True if successful."""
    if description:
        print_step(description)
    print(f"   Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    try:
        result = subprocess.run(cmd, check=True, cwd=PROJECT_ROOT)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        print_error(f"Command failed with exit code {e.returncode}: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        return False
    except Exception as e:
        print_error(f"Failed to run command: {e}")
        return False


def setup_venv():
    """Create and activate virtual environment."""
    print_header("Setting Up Virtual Environment")
    
    if VENV_DIR.exists():
        print_step(f"Virtual environment already exists at {VENV_DIR}")
        return True
    
    print_step(f"Creating virtual environment at {VENV_DIR}")
    try:
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        print_success(f"Virtual environment created")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to create virtual environment: {e}")
        return False


def install_dependencies():
    """Install required dependencies."""
    print_header("Installing Dependencies")
    
    if not VENV_PYTHON.exists():
        print_error(f"Virtual environment python not found at {VENV_PYTHON}")
        return False
    
    print_step(f"Installing packages: {', '.join(DEPENDENCIES)}")
    try:
        subprocess.run(
            [str(VENV_PYTHON), "-m", "pip", "install", "-q"] + DEPENDENCIES,
            check=True,
            cwd=PROJECT_ROOT
        )
        print_success("Dependencies installed")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dependencies: {e}")
        return False


def init_ca():
    """Initialize the Certificate Authority."""
    print_header("Initializing Certificate Authority")
    
    if not VENV_PYTHON.exists():
        print_error(f"Virtual environment python not found at {VENV_PYTHON}")
        return False
    
    # Remove existing ca and keys directories
    ca_dir = PROJECT_ROOT / "ca"
    keys_dir = PROJECT_ROOT / "keys"
    
    if ca_dir.exists():
        print_step(f"Removing existing CA directory: {ca_dir}")
        shutil.rmtree(ca_dir)
    
    if keys_dir.exists():
        print_step(f"Removing existing keys directory: {keys_dir}")
        shutil.rmtree(keys_dir)
    
    # Run ca_tool.py init
    print_step("Initializing CA with ca_tool.py init")
    try:
        result = subprocess.run(
            [str(VENV_PYTHON), str(CA_TOOL), "init"],
            check=True,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True
        )
        print(f"   {result.stdout.strip()}")
        print_success("CA initialized")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"CA initialization failed: {e.stderr}")
        return False


def generate_certificates(users=None):
    """Generate certificates for specified users."""
    if users is None:
        users = DEFAULT_USERS
    
    print_header(f"Generating Certificates for Users: {', '.join(users)}")
    
    if not VENV_PYTHON.exists():
        print_error(f"Virtual environment python not found at {VENV_PYTHON}")
        return False
    
    for username in users:
        # Generate keys
        print_step(f"Generating keys for {username}")
        try:
            result = subprocess.run(
                [str(VENV_PYTHON), str(CA_TOOL), "genkeys", username],
                check=True,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True
            )
            print(f"   {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            print_error(f"Key generation failed for {username}: {e.stderr}")
            return False
        
        # Issue certificate
        print_step(f"Issuing certificate for {username}")
        try:
            result = subprocess.run(
                [str(VENV_PYTHON), str(CA_TOOL), "issue", username],
                check=True,
                cwd=PROJECT_ROOT,
                capture_output=True,
                text=True
            )
            print(f"   {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            print_error(f"Certificate issuance failed for {username}: {e.stderr}")
            return False
    
    print_success(f"Generated certificates for {len(users)} user(s)")
    return True


def clean_all():
    """Clean up generated files and virtual environment."""
    print_header("Cleaning Up")
    
    dirs_to_remove = [
        (VENV_DIR, "virtual environment"),
        (PROJECT_ROOT / "ca", "CA directory"),
        (PROJECT_ROOT / "keys", "keys directory"),
        (PROJECT_ROOT / "__pycache__", "__pycache__"),
    ]
    
    for path, description in dirs_to_remove:
        if path.exists():
            print_step(f"Removing {description}: {path}")
            shutil.rmtree(path)
    
    print_success("Cleanup complete")
    return True


def run_tests():
    """Run the test suite."""
    print_header("Running Tests")
    
    if not VENV_PYTHON.exists():
        print_error(f"Virtual environment python not found at {VENV_PYTHON}")
        return False
    
    print_step("Running pytest")
    try:
        result = subprocess.run(
            [str(VENV_PYTHON), "-m", "pytest", "-q"],
            cwd=PROJECT_ROOT,
            check=False
        )
        return result.returncode == 0
    except Exception as e:
        print_error(f"Failed to run tests: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Python-friendly setup script for First Contact Protocol.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python setup.py init                          # Setup venv and install deps
  python setup.py keygen                        # Generate certs for default users
  python setup.py keygen --users Alice Bob      # Generate certs for custom users
  python setup.py clean                         # Remove generated files
  python setup.py all                           # Full setup (init + keygen)
  python setup.py test                          # Run tests
  python setup.py run --user Pilot-Alpha --port 7001  # Run a client
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # init command
    subparsers.add_parser("init", help="Setup venv, install deps, and initialize CA")
    
    # keygen command
    keygen_parser = subparsers.add_parser("keygen", help="Generate user certificates")
    keygen_parser.add_argument(
        "--users",
        nargs="+",
        default=DEFAULT_USERS,
        help=f"List of usernames (default: {' '.join(DEFAULT_USERS)})"
    )
    
    # clean command
    subparsers.add_parser("clean", help="Remove generated files and venv")
    
    # all command (setup + keygen)
    all_parser = subparsers.add_parser("all", help="Full setup: init + keygen")
    all_parser.add_argument(
        "--users",
        nargs="+",
        default=DEFAULT_USERS,
        help=f"List of usernames (default: {' '.join(DEFAULT_USERS)})"
    )
    
    # test command
    subparsers.add_parser("test", help="Run the test suite")
    
    # run command
    run_parser = subparsers.add_parser("run", help="Run a client")
    run_parser.add_argument("--user", required=True, help="Username to run as")
    run_parser.add_argument("--port", type=int, required=True, help="Port to listen on")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    success = True
    
    if args.command == "init":
        success = setup_venv() and install_dependencies() and init_ca()
    
    elif args.command == "keygen":
        success = generate_certificates(args.users)
    
    elif args.command == "clean":
        success = clean_all()
    
    elif args.command == "all":
        success = (
            setup_venv() and
            install_dependencies() and
            init_ca() and
            generate_certificates(args.users)
        )
    
    elif args.command == "test":
        success = run_tests()
    
    elif args.command == "run":
        if not VENV_PYTHON.exists():
            print_error(f"Virtual environment not found at {VENV_DIR}")
            success = False
        else:
            print_header(f"Running Client: {args.user} on Port {args.port}")
            try:
                os.environ["USER_ID"] = args.user
                os.environ["LISTEN_TCP_PORT"] = str(args.port)
                result = subprocess.run(
                    [str(VENV_PYTHON), "-m", "app.cli"],
                    cwd=PROJECT_ROOT
                )
                success = result.returncode == 0
            except Exception as e:
                print_error(f"Failed to run client: {e}")
                success = False
    
    if success:
        print_success("Operation completed successfully")
        sys.exit(0)
    else:
        print_error("Operation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
