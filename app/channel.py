import ssl
import threading
from typing import Optional, Callable

# Import necessary utilities using relative path
from .utils import COLOR_PEER, COLOR_ERROR, COLOR_RESET, MY_USER_ID

try:
    from ssl import SSLWantReadError
except ImportError:
    class SSLWantReadError(Exception):
        pass

class SessionState:
    """Holds the active SSL connection and the peer's identity."""
    def __init__(self, peer_id: str, conn: ssl.SSLSocket):
        self.peer_id = peer_id
        self.conn = conn
        self._closed = False
    
    def close(self):
        """Safely close the connection."""
        if not self._closed:
            try:
                self.conn.close()
            except:
                pass
            self._closed = True
    
    def is_closed(self):
        return self._closed

def recv_loop(conn: ssl.SSLSocket, peer_id: str, on_disconnect: Optional[Callable] = None):
    """Handles continuous secure reading in a background thread.
    
    Args:
        conn: The SSL socket to read from
        peer_id: The identifier of the peer
        on_disconnect: Optional callback function to call when connection is lost
    """
    
    # Ensure the socket is in blocking mode for reliable reading
    conn.settimeout(None) 
    
    while True:
        try:
            # Use a large buffer for reliable reading
            data = conn.read(4096) 
            
            if not data:
                # Peer performed a graceful close (empty read on open socket)
                raise ConnectionResetError("Peer closed connection")
            
            # Print decrypted message
            print(f"\n{COLOR_PEER}[{peer_id}] > {data.decode()}{COLOR_RESET}")
            print(f"\n> ", end="", flush=True)

        except SSLWantReadError:
            # If the read operation would block, continue waiting
            continue 
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            print(f"\n{COLOR_ERROR}[ERROR] Connection lost with {peer_id}.{COLOR_RESET}")
            break
        except Exception as e:
            # Catch general errors, including unexpected drops
            print(f"\n{COLOR_ERROR}[ERROR] Receive error: {e}{COLOR_RESET}")
            break
    
    # Clean up and notify
    try:
        conn.close()
    except:
        pass
    
    if on_disconnect:
        on_disconnect()

def chat_send(conn: ssl.SSLSocket, message: str) -> bool:
    """Encrypts and sends a message over the established TLS connection.
    
    Args:
        conn: The SSL socket to write to
        message: The message to send
        
    Returns:
        True if successful, False otherwise
    """
    
    try:
        conn.write(message.encode('utf-8'))
        return True
    except (BrokenPipeError, OSError) as e:
        print(f"{COLOR_ERROR}[ERROR] Failed to send: Connection lost{COLOR_RESET}")
        return False
    except Exception as e:
        print(f"{COLOR_ERROR}[ERROR] Failed to send: {e}{COLOR_RESET}")
        return False