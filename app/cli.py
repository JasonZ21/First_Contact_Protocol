import sys
import threading
import socket
import ssl
from typing import Optional
from threading import Lock

# Import everything from the other modules
from .utils import COLOR_SUCCESS, COLOR_ME, MY_USER_ID, LISTEN_TCP_PORT
from .utils import COLOR_RESET, COLOR_ERROR, create_ssl_context
from .handshake import initiate_tls_handshake, handle_incoming_connection
from .channel import SessionState, recv_loop, chat_send

class TLSClient:
    def __init__(self):
        self._running = True
        self.active_conn: Optional[SessionState] = None
        self._conn_lock = Lock()
        self._listener_sock: Optional[socket.socket] = None

    def _on_disconnect(self):
        """Callback when connection is lost."""
        with self._conn_lock:
            if self.active_conn:
                self.active_conn.close()
                self.active_conn = None
        print(f"\n{COLOR_ERROR}[INFO] Disconnected. Ready for new connection.{COLOR_RESET}")
        print("\n> ", end="", flush=True)

    # --- Server/Responder Logic ---
    def _tcp_listener_loop(self):
        """Background thread that listens for incoming TLS connections."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener_sock = sock

        try:
            sock.bind(('0.0.0.0', LISTEN_TCP_PORT))
            sock.listen(1)
            sock.settimeout(1.0)  # Allow periodic checks of _running flag
        except Exception as e:
            print(f"{COLOR_ERROR}FATAL: Could not bind to port {LISTEN_TCP_PORT}. Error: {e}{COLOR_RESET}")
            self.shutdown()
            return
        
        print(f"Listening for TLS connection on port {LISTEN_TCP_PORT}...")
        
        while self._running:
            try:
                raw_conn, addr = sock.accept()
                
                # Check if already connected
                with self._conn_lock:
                    if self.active_conn and not self.active_conn.is_closed():
                        print(f"\n{COLOR_ERROR}[INFO] Connection from {addr[0]} rejected: already connected{COLOR_RESET}")
                        raw_conn.close()
                        continue
                
                session = handle_incoming_connection(raw_conn, addr)
                
                if session:
                    print(f"{COLOR_SUCCESS}[SUCCESS] TLS established. Peer ID: {session.peer_id}{COLOR_RESET}")
                    
                    # Update session state
                    with self._conn_lock:
                        self.active_conn = session
                    
                    # Start receive thread with disconnect callback
                    threading.Thread(
                        target=recv_loop, 
                        args=(session.conn, session.peer_id, self._on_disconnect), 
                        daemon=True
                    ).start()

            except socket.timeout:
                continue  # Check _running flag
            except Exception as e:
                if self._running:  # Only print if not shutting down
                    pass  # Handshake errors already printed

        # Clean up listener socket
        try:
            sock.close()
        except:
            pass

    # --- Client/Initiator Logic ---
    def connect_peer(self, ip: str, port: int):
        """Initiate a connection to a peer."""
        with self._conn_lock:
            if self.active_conn and not self.active_conn.is_closed():
                print(f"{COLOR_ERROR}ERROR: Already connected. Use 'disconnect' first.{COLOR_RESET}")
                return

        print(f"Attempting secure connection to {ip}:{port}...")
        
        session = initiate_tls_handshake(ip, port)
        
        if session:
            print(f"{COLOR_SUCCESS}[SUCCESS] TLS established. Peer ID: {session.peer_id}{COLOR_RESET}")
            
            with self._conn_lock:
                self.active_conn = session
            
            # Start receive thread with disconnect callback
            threading.Thread(
                target=recv_loop, 
                args=(session.conn, session.peer_id, self._on_disconnect), 
                daemon=True
            ).start()

    def disconnect(self):
        """Manually disconnect from current peer."""
        with self._conn_lock:
            if not self.active_conn or self.active_conn.is_closed():
                print("ERROR: Not connected.")
                return
            
            self.active_conn.close()
            self.active_conn = None
            print(f"{COLOR_SUCCESS}Disconnected successfully.{COLOR_RESET}")

    def send_message(self, message: str):
        """Send a message to the connected peer."""
        with self._conn_lock:
            if not self.active_conn or self.active_conn.is_closed():
                print(f"{COLOR_ERROR}ERROR: Not connected.{COLOR_RESET}")
                return
            
            success = chat_send(self.active_conn.conn, message)
            
            if success:
                print(f"{COLOR_ME}[Me] > {message}{COLOR_RESET}")
            else:
                # Connection lost during send
                self.active_conn.close()
                self.active_conn = None

    def show_status(self):
        """Display current connection status."""
        with self._conn_lock:
            if self.active_conn and not self.active_conn.is_closed():
                print(f"{COLOR_SUCCESS}Status: Connected to {self.active_conn.peer_id}{COLOR_RESET}")
            else:
                print(f"{COLOR_ERROR}Status: Not connected{COLOR_RESET}")
            
    def run(self):
        """Main client loop."""
        threading.Thread(target=self._tcp_listener_loop, daemon=True).start()
        print(f"{COLOR_SUCCESS}\n*** First Contact Client (TLS/Certificate Demo) ***{COLOR_RESET}")
        print(f"My ID: {MY_USER_ID} | Listening on port {LISTEN_TCP_PORT}")
        print("\nCommands:")
        print("  connect <IP> <PORT>  - Connect to a peer")
        print("  send <MSG>           - Send a message")
        print("  disconnect           - Close current connection")
        print("  status               - Show connection status")
        print("  exit                 - Quit the application")
        
        try:
            while self._running:
                user_input = input("\n> ").strip()
                if not user_input: 
                    continue
                
                parts = user_input.split(maxsplit=1)
                command = parts[0].lower()
                
                if command == 'connect':
                    args = user_input.split()
                    if len(args) == 3:
                        ip, port_str = args[1], args[2]
                        try:
                            self.connect_peer(ip, int(port_str))
                        except ValueError: 
                            print(f"{COLOR_ERROR}Invalid port number.{COLOR_RESET}")
                    else: 
                        print(f"{COLOR_ERROR}Usage: connect <IP> <PORT>{COLOR_RESET}")
                
                elif command == 'send':
                    if len(parts) < 2: 
                        print(f"{COLOR_ERROR}Usage: send <message>{COLOR_RESET}")
                    else:
                        message = parts[1]
                        self.send_message(message)
                
                elif command == 'disconnect':
                    self.disconnect()
                
                elif command == 'status':
                    self.show_status()
                
                elif command == 'exit' or command == 'quit':
                    break
                
                else: 
                    print(f"{COLOR_ERROR}Unknown command: {command}{COLOR_RESET}")
                    
        except KeyboardInterrupt: 
            print()  # New line after ^C
        finally: 
            self.shutdown()

    def shutdown(self):
        """Clean shutdown of the client."""
        print("\nShutting down client...")
        self._running = False
        
        # Close active connection
        with self._conn_lock:
            if self.active_conn:
                self.active_conn.close()
        
        # Close listener socket to unblock accept()
        if self._listener_sock:
            try:
                self._listener_sock.close()
            except:
                pass

if __name__ == "__main__":
    client = TLSClient()
    client.run()