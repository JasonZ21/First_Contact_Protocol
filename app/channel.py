import ssl
import threading
from typing import Optional

# Import necessary utilities using relative path
from .utils import COLOR_PEER, COLOR_ERROR,COLOR_RESET, MY_USER_ID

try:
    # Python 3.7+ uses BlockingIOError for non-blocking read failures
    from ssl import SSLWantReadError
except ImportError:
    # Use fallback if SSLWantReadError isn't directly exposed
    class SSLWantReadError(Exception):
        pass

class SessionState:
    """Holds the active SSL connection and the peer's identity."""
    def __init__(self, peer_id: str, conn: ssl.SSLSocket):
        self.peer_id = peer_id
        self.conn = conn

def recv_loop(conn: ssl.SSLSocket, peer_id: str, active_conn_ref: dict):
    """Handles continuous secure reading in a background thread."""
    
    # Ensure the socket is in blocking mode for reliable reading (default, but confirm)
    conn.settimeout(None) 
    
    while True:
        try:
            # Use a large buffer for reliable reading
            data = conn.read(4096) 
            
            if not data:
                # Peer performed a graceful close (empty read on open socket)
                raise ConnectionResetError 
            
            # Print decrypted message
            print(f"\n{COLOR_PEER}[{peer_id}] > {data.decode()}{COLOR_RESET}")
            print(f"\n> ", end="", flush=True)

        except SSLWantReadError:
            # FIX: If the read operation would block (i.e., no data is immediately available), 
            # we simply continue the loop. This prevents the thread from crashing on idle time.
            continue 
        except ConnectionResetError:
            print(f"\n{COLOR_ERROR}[ERROR] Connection lost with {peer_id}.{COLOR_RESET}")
            conn.close()
            active_conn_ref['conn'] = None
            break
        except Exception as e:
            # Catch general errors, including unexpected drops
            print(f"\n{COLOR_ERROR}[ERROR] Receive error: {e}{COLOR_RESET}")
            conn.close()
            active_conn_ref['conn'] = None
            break

def chat_send(conn: ssl.SSLSocket, message: str, user_id: str):
    """Encrypts and sends a message over the established TLS connection."""
    
    try:
        conn.write(message.encode('utf-8'))
        return True
    except Exception as e:
        print(f"Failed to send: {e}")
        conn.close()
        return False