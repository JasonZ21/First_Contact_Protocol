"""
Helpers to create a root CA, issue identity certs (Ed25519), create expired certs,
and an alternative (attacker) root.

Implements:
- make_root_ca()
- issue_cert(subject_name, issuer, issuer_key, not_before=None, not_after=None)
- keypair generation helper (Ed25519, X25519)
"""

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from datetime import datetime, timedelta, timezone
from typing import Tuple, Dict
import secrets

def make_root_ca(name: str="Test Root") -> dict:
    """
    Returns dict: {'private key': <Ed25519PrivateKey>, 'cert': <x509.Certificate>}
    """
    # create Ed25519 key, self signed X.509 with long expiry
    raise NotImplementedError

def issue_cert(subject_name: str, issuer: dict, valid_days: int = 30) -> dict:
    """
    Issue a leaf cert for subject name signed by issuer (root or intermediate)
    Returns {'private key': <Ed25519PrivateKey>, 'cert': <x509.Certificate>}
    """
    raise NotImplementedError

def make_id_keys(subject_name: str, issuer: dict, valid_days:int=30) -> dict:
    """
    Convenience: create keypair + cert packaged in dict for tests to consume.
    """
    return issue_cert(subject_name, issuer, valid_days=valid_days)