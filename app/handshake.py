import socket
import ssl
from typing import Optional
from .utils import create_ssl_context, get_common_name, COLOR_ERROR, COLOR_RESET
from . import utils

# Import necessary channel classes using relative path
from .channel import SessionState, recv_loop

# Certificate validation (enforces CRL checks)
import certificate_validation
from cryptography import x509
from cryptography.hazmat.primitives import serialization

def initiate_tls_handshake(ip: str, port: int) -> Optional[SessionState]:
    """Client (Initiator) connects and performs mutual TLS handshake."""
    try:
        raw_sock = socket.create_connection((ip, port), timeout=5)
        context = create_ssl_context(is_server=False)
        
        # Performs the TLS Handshake
        ssl_conn = context.wrap_socket(raw_sock, server_hostname=ip)

        # Get the peer certificate in binary and also a subject dict for CN
        der = ssl_conn.getpeercert(binary_form=True)
        peer_cert_dict = ssl_conn.getpeercert()
        peer_id = get_common_name(peer_cert_dict['subject'])

        # Validate certificate (this enforces CRL checks in certificate_validation)
        try:
            if der is None:
                raise ValueError("No peer certificate presented")
            peer_cert_obj = x509.load_der_x509_certificate(der)
            peer_pem = peer_cert_obj.public_bytes(serialization.Encoding.PEM)
            with open(utils.CA_ROOT_PATH, 'rb') as f:
                ca_pem = f.read()

            # This will raise ValueError on mismatch/expiry/revocation
            certificate_validation.validate_cert(peer_pem, ca_pem, peer_id)
        except Exception as e:
            try:
                ssl_conn.close()
            except Exception:
                pass
            print(f"{COLOR_ERROR}[ERROR] TLS Handshake failed (Authentication failure): {e}{COLOR_RESET}")
            return None

        return SessionState(peer_id, ssl_conn)

    except ssl.SSLError as e:
        print(f"{COLOR_ERROR}[ERROR] TLS Handshake failed (Authentication failure): {e}{COLOR_RESET}")
        return None
    except Exception as e:
        print(f"Connection failed: {e}")
        return None


def handle_incoming_connection(raw_conn, addr) -> Optional[SessionState]:
    """Server (Responder) accepts connection and performs mutual TLS handshake."""
    try:
        context = create_ssl_context(is_server=True)
        print(f"\n[+] Incoming connection from {addr[0]}:{addr[1]}. Initiating TLS handshake...")

        # Performs the TLS Handshake
        ssl_conn = context.wrap_socket(raw_conn, server_side=True)

        # Retrieve peer cert and perform validation (including CRL)
        der = ssl_conn.getpeercert(binary_form=True)
        peer_cert_dict = ssl_conn.getpeercert()
        peer_id = get_common_name(peer_cert_dict['subject'])

        try:
            if der is None:
                raise ValueError("No peer certificate presented")
            peer_cert_obj = x509.load_der_x509_certificate(der)
            peer_pem = peer_cert_obj.public_bytes(serialization.Encoding.PEM)
            with open(utils.CA_ROOT_PATH, 'rb') as f:
                ca_pem = f.read()

            certificate_validation.validate_cert(peer_pem, ca_pem, peer_id)
        except Exception as e:
            try:
                ssl_conn.close()
            except Exception:
                pass
            print(f"{COLOR_ERROR}[ERROR] TLS Handshake failed (Authentication failure): {e}{COLOR_RESET}")
            return None

        return SessionState(peer_id, ssl_conn)

    except ssl.SSLError as e:
        print(f"{COLOR_ERROR}[ERROR] TLS Handshake failed (Authentication failure): {e}{COLOR_RESET}")
        return None
    except Exception as e:
        print(f"[ERROR] Listener/Connection error: {e}")
        return None