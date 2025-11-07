from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def validate_cert(peer_cert_pem, ca_cert_pem, expected_name):
    peer_cert = x509.load_pem_x509_certificate(peer_cert_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    # Verify signature
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        peer_cert.signature,
        peer_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        peer_cert.signature_hash_algorithm,
    )

    # Check subject name matches expected
    cn = peer_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    if cn != expected_name:
        raise ValueError(f"Identity mismatch: expected {expected_name}, got {cn}")

    # Check validity
    now = datetime.datetime.utcnow()
    if not (peer_cert.not_valid_before <= now <= peer_cert.not_valid_after):
        raise ValueError("Certificate expired or not yet valid")

    print(f"{expected_name} certificate valid and trusted.")
    return True
