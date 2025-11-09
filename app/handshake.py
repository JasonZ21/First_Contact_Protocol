import socket
import ssl
from typing import Optional
from .utils import create_ssl_context, get_common_name, COLOR_ERROR

# Import necessary channel classes using relative path
from .channel import SessionState, recv_loop 

def initiate_tls_handshake(ip: str, port: int) -> Optional[SessionState]:
    """Client (Initiator) connects and performs mutual TLS handshake."""
    try:
        raw_sock = socket.create_connection((ip, port), timeout=5)
        context = create_ssl_context(is_server=False)
        
        # Performs the TLS Handshake
        ssl_conn = context.wrap_socket(raw_sock, server_hostname=ip)

        peer_cert = ssl_conn.getpeercert()
        peer_id = get_common_name(peer_cert['subject'])
        
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
        
        peer_cert = ssl_conn.getpeercert()
        peer_id = get_common_name(peer_cert['subject'])
        
        return SessionState(peer_id, ssl_conn)

    except ssl.SSLError as e:
        print(f"{COLOR_ERROR}[ERROR] TLS Handshake failed (Authentication failure): {e}{COLOR_RESET}")
        return None
    except Exception as e:
        print(f"[ERROR] Listener/Connection error: {e}")
        return None