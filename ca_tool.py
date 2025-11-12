import sys
import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from build_ca import create_ca, issue_cert 
import crl
import merkle_log
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def generate_user_keypair(username: str):
    """Generates an RSA key pair for a user and saves them in the keys/ directory."""
    
    # 1. Generate RSA Private Key
    # NOTE: Key size must match CA's expectations (2048 here, same as build_ca.py)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = key.public_key()
    
    # 2. Setup directory
    keys_dir = "keys"
    os.makedirs(keys_dir, exist_ok=True)
    
    # Define file paths
    key_path = os.path.join(keys_dir, f"{username}_key.pem")
    pub_path = os.path.join(keys_dir, f"{username}_pub.pem")

    # 3. Save Private Key
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # 4. Save Public Key
    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print(f"Generated key pair for {username}: {key_path}, {pub_path}")
    return pub_path


# =========================================================
# Main CA Tool CLI Logic
# =========================================================

def main():
    parser = argparse.ArgumentParser(description="First Contact Protocol Certificate Authority Tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command: Init
    subparsers.add_parser("init", help="Initializes the Root CA.")
    
    # Command: GenKeys
    genkeys_parser = subparsers.add_parser("genkeys", help="Generates user key pairs.")
    genkeys_parser.add_argument("username", help="The username for the keypair (e.g., Pilot-Alpha).")

    # Command: Issue
    issue_parser = subparsers.add_parser("issue", help="Issues a certificate for an existing public key.")
    issue_parser.add_argument("username", help="The username whose public key to certify.")

    # Command: Revoke
    revoke_parser = subparsers.add_parser("revoke", help="Revokes a user's certificate.")
    revoke_parser.add_argument("username", help="The username whose certificate to revoke.")

    # Command: CRL
    subparsers.add_parser("crl", help="Print the current Certificate Revocation List.")

    # Command: Renew
    renew_parser = subparsers.add_parser("renew", help="Renew a user's certificate (short-lived).")
    renew_parser.add_argument("username", help="The username whose certificate to renew.")
    
    args = parser.parse_args()

    if args.command == "init":
        create_ca()
        
    elif args.command == "genkeys":
        generate_user_keypair(args.username)

    elif args.command == "issue":
        pub_key_path = os.path.join("keys", f"{args.username}_pub.pem")
        cert_path = os.path.join("keys", f"{args.username}_cert.pem")
        
        if not os.path.exists(pub_key_path):
            print(f"Error: Public key not found for {args.username}. Run 'genkeys {args.username}' first.")
            sys.exit(1)

        with open(pub_key_path, "rb") as f:
            user_pubkey_pem = f.read()

        # Call certificate issuance function (default validity can be set via env)
        # Short-lived certs: allow override via env var CERT_VALID_DAYS
        try:
            valid_days = int(os.environ.get("CERT_VALID_DAYS", "30"))
        except Exception:
            valid_days = 30

        cert_pem = issue_cert(args.username, user_pubkey_pem, valid_days=valid_days)
        
        with open(cert_path, "wb") as f:
            f.write(cert_pem)
            
        # Append to transparency log
        try:
            info = merkle_log.append_cert(cert_pem)
            print(f"Appended cert to Merkle log index={info['index']} root={info['root']}")
        except Exception:
            print("Warning: failed to append cert to Merkle log")

        print(f"Issued certificate for {args.username} at {cert_path}")

    elif args.command == "revoke":
        # Revoke certificate for username (looks up certificate and revokes its serial)
        cert_path = os.path.join("keys", f"{args.username}_cert.pem")
        if not os.path.exists(cert_path):
            print(f"Error: Certificate not found for {args.username} at {cert_path}")
            sys.exit(1)
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        serial = cert.serial_number
        ok = crl.revoke(serial)
        if ok:
            print(f"Revoked certificate serial={serial} for {args.username}")
        else:
            print(f"Certificate serial={serial} was already revoked")

    elif args.command == "crl":
        # Print CRL
        try:
            data = crl._load_raw_crl()
            print("CRL updated:", data.get("updated_at"))
            for e in data.get("revoked", []):
                print(f" - serial={e['serial']} revoked_at={e['revoked_at']} reason={e.get('reason')}")
        except Exception as e:
            print("Error reading CRL:", e)

    elif args.command == "renew":
        # Renew certificate for username: re-issue a cert for existing public key
        pub_key_path = os.path.join("keys", f"{args.username}_pub.pem")
        cert_path = os.path.join("keys", f"{args.username}_cert.pem")
        if not os.path.exists(pub_key_path):
            print(f"Error: Public key not found for {args.username}. Run 'genkeys {args.username}' first.")
            sys.exit(1)
        with open(pub_key_path, "rb") as f:
            user_pubkey_pem = f.read()
        try:
            # Renewals typically create short-lived certs; configurable via env
            try:
                valid_days = int(os.environ.get("RENEW_VALID_DAYS", "7"))
            except Exception:
                valid_days = 7
            cert_pem = issue_cert(args.username, user_pubkey_pem, valid_days=valid_days)
            with open(cert_path, "wb") as f:
                f.write(cert_pem)
            merkle_log.append_cert(cert_pem)
            print(f"Renewed certificate for {args.username}, saved to {cert_path}")
        except Exception as e:
            print(f"Renewal failed: {e}")

if __name__ == "__main__":
    main()