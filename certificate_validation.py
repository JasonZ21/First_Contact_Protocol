from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ed25519
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import os
import crl


def validate_cert(peer_cert_pem, ca_cert_pem, expected_name):
    peer_cert = x509.load_pem_x509_certificate(peer_cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    # Verify signature. Support RSA and Ed25519 public keys used in tests and CA.
    ca_pub = ca_cert.public_key()
    try:
        sig_hash = getattr(peer_cert, "signature_hash_algorithm", None)

        # If the certificate signature is a raw algorithm with no hash (e.g., Ed25519)
        # then signature_hash_algorithm may be None and verification should be done
        # without padding/hash objects.
        if sig_hash is None:
            # Perform raw verify for pure-signature algorithms (e.g., Ed25519).
            # If the CA key is RSA and the cert has no hash algorithm, that's unsupported.
            if isinstance(ca_pub, rsa.RSAPublicKey):
                raise ValueError("Certificate signature algorithm incompatible with RSA public key")
            ca_pub.verify(peer_cert.signature, peer_cert.tbs_certificate_bytes)
        else:
            # Prefer RSA-style verification when the CA key is RSA
            if isinstance(ca_pub, rsa.RSAPublicKey):
                ca_pub.verify(
                    peer_cert.signature,
                    peer_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    sig_hash,
                )
            else:
                # Fallback for other key types which expect a hash-based API
                ca_pub.verify(
                    peer_cert.signature,
                    peer_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    sig_hash,
                )
    except Exception as e:
        raise ValueError(f"Certificate signature verification failed: {e}")

    # Check subject name matches expected
    cn = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if cn != expected_name:
        raise ValueError(f"Identity mismatch: expected {expected_name}, got {cn}")

    # Check validity (use UTC-aware properties when available to avoid deprecation warnings)
    # Use timezone-aware UTC datetimes for comparison to avoid deprecation and tz issues
    def _to_utc(dt):
        if dt is None:
            return None
        if getattr(dt, 'tzinfo', None) is None:
            return dt.replace(tzinfo=datetime.timezone.utc)
        return dt.astimezone(datetime.timezone.utc)

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = _to_utc(getattr(peer_cert, "not_valid_before_utc", None) or peer_cert.not_valid_before)
    not_after = _to_utc(getattr(peer_cert, "not_valid_after_utc", None) or peer_cert.not_valid_after)
    if not (not_before <= now <= not_after):
        raise ValueError("Certificate expired or not yet valid")

    # Check against CRL if present
    try:
        serial = int(peer_cert.serial_number)
        # Only enforce CRL if a CRL file exists
        if os.path.exists(crl.CRL_PATH):
            # Verify CRL signature first
            try:
                ca_pub = ca_cert.public_key()
                if not crl.verify_crl_signature(ca_pub):
                    raise ValueError("CRL signature invalid or missing")
            except Exception as e:
                # If CRL exists but verification fails, fail closed
                raise ValueError(f"CRL verification failed: {e}")

            if crl.is_revoked(serial):
                raise ValueError("Certificate has been revoked (CRL)")
    except ValueError:
        # Re-raise validation errors
        raise
    except Exception:
        # If an unexpected error occurred during CRL checking, fail closed
        raise

    print(f"{expected_name} certificate valid and trusted.")
    return True
