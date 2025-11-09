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
import ipaddress

def make_root_ca(name: str="Test Root") -> dict:
    """
    Returns dict: {'private key': <Ed25519PrivateKey>, 'cert': <x509.Certificate>}
    """
    # create Ed25519 key, self signed X.509 with long expiry
    key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now - timedelta(days=1))
    builder = builder.not_valid_after(now + timedelta(days=3650))
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    # Add key usage and key identifier extensions for CA
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True,
                                                  content_commitment=False,
                                                  key_encipherment=False,
                                                  data_encipherment=False,
                                                  key_agreement=False,
                                                  key_cert_sign=True,
                                                  crl_sign=True,
                                                  encipher_only=False,
                                                  decipher_only=False), critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
    cert = builder.sign(private_key=key, algorithm=None)
    return {'private_key': key, 'cert': cert}

def issue_cert(subject_name: str, issuer: dict, valid_days: int = 30) -> dict:
    """
    Issue a leaf cert for subject name signed by issuer (root or intermediate)
    Returns {'private key': <Ed25519PrivateKey>, 'cert': <x509.Certificate>}
    """
    key = ed25519.Ed25519PrivateKey.generate()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    issuer_cert = issuer['cert']
    issuer_key = issuer['private_key']
    now = datetime.now(timezone.utc)
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer_cert.subject)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(now - timedelta(minutes=1))
    builder = builder.not_valid_after(now + timedelta(days=valid_days))
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    # Add key usage and identifiers for leaf
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True,
                                                  content_commitment=False,
                                                  key_encipherment=False,
                                                  data_encipherment=False,
                                                  key_agreement=False,
                                                  key_cert_sign=False,
                                                  crl_sign=False,
                                                  encipher_only=False,
                                                  decipher_only=False), critical=True)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    builder = builder.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    cert = builder.sign(private_key=issuer_key, algorithm=None)
    return {'private_key': key, 'cert': cert}

def make_id_keys(subject_name: str, issuer: dict, valid_days:int=30) -> dict:
    """
    Convenience: create keypair + cert packaged in dict for tests to consume.
    """
    return issue_cert(subject_name, issuer, valid_days=valid_days)