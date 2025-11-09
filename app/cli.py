import sys
import threading
import socket
import ssl
from typing import Optional

# Import everything from the other modules
from .utils import COLOR_SUCCESS, COLOR_ME, MY_USER_ID, LISTEN_TCP_PORT
from .utils import COLOR_RESET, COLOR_ERROR, create_ssl_context
from .handshake import initiate_tls_handshake, handle_incoming_connection
from .channel import SessionState, recv_loop, chat_send

class TLSClient:
    def __init__(self):
        # Initial check for key files is handled in the utility context creation
        self._running = True
        self.active_conn: Optional[ssl.SSLSocket] = None

    # --- Server/Responder Logic ---
    def _tcp_listener_loop(self):
        # We need a dictionary wrapper to allow the thread to update the class member
        active_conn_ref = {'conn': None}
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind(('0.0.0.0', LISTEN_TCP_PORT))
            sock.listen(1)
        except Exception as e:
            print(f"{COLOR_ERROR}FATAL: Could not bind to port {LISTEN_TCP_PORT}. Error: {e}{COLOR_RESET}")
            self.shutdown()
            return
        
        print(f"Listening for TLS connection on port {LISTEN_TCP_PORT}...")
        
        while self._running:
            try:
                raw_conn, addr = sock.accept()
                
                session = handle_incoming_connection(raw_conn, addr)
                
                if session:
                    print(f"{COLOR_SUCCESS}[SUCCESS] TLS established. Peer ID: {session.peer_id}{COLOR_RESET}")
                    
                    # Update main session state and start receive thread
                    self.active_conn = session.conn
                    active_conn_ref['conn'] = session.conn
                    
                    threading.Thread(target=recv_loop, args=(session.conn, session.peer_id, active_conn_ref), daemon=True).start()

            except Exception:
                # Listener closed or Handshake failed (already printed error)
                pass

    # --- Client/Initiator Logic ---
    def connect_peer(self, ip: str, port: int):
        if self.active_conn:
            print("ERROR: Already connected. Disconnect first.")
            return

        print(f"Attempting secure connection to {ip}:{port}...")
        
        session = initiate_tls_handshake(ip, port)
        
        if session:
            print(f"{COLOR_SUCCESS}[SUCCESS] TLS established. Peer ID: {session.peer_id}{COLOR_RESET}")
            self.active_conn = session.conn
            
            # We need a reference dictionary to pass to the thread for self.active_conn updates
            active_conn_ref = {'conn': session.conn} 
            
            threading.Thread(target=recv_loop, args=(session.conn, session.peer_id, active_conn_ref), daemon=True).start()

    def chat_send(self, message: str):
        if not self.active_conn:
            print("ERROR: Not connected.")
            return
            
        # Call the standalone chat_send function
        chat_send(self.active_conn, message, MY_USER_ID)
            
    def run(self):
        threading.Thread(target=self._tcp_listener_loop, daemon=True).start()
        print(f"{COLOR_SUCCESS}\n*** First Contact Client (TLS/Certificate Demo) ***{COLOR_RESET}")
        print(f"My ID: {MY_USER_ID} | Listening on port {LISTEN_TCP_PORT}")
        print("Commands: connect <IP> <PORT>, send <MSG>, exit")
        
        try:
            while self._running:
                user_input = input("\n> ").strip()
                if not user_input: continue
                
                parts = user_input.split(maxsplit=2)
                command = parts[0].lower()
                
                if command == 'connect':
                    if len(parts) == 3:
                        ip, port_str = parts[1], parts[2]
                        try:
                            self.connect_peer(ip, int(port_str))
                        except ValueError: print("Invalid port number.")
                    else: print("Usage: connect <IP> <PORT>")
                elif command == 'send':
                    if len(parts) < 2: 
                        print("Usage: send <message>")
                    else:
                        message_to_send = ' '.join(user_input.split(' ')[1:])
                        self.chat_send(message_to_send)
                elif command == 'exit': break
                else: print(f"Unknown command: {command}")
                    
        except KeyboardInterrupt: pass
        finally: self.shutdown()

    def shutdown(self):
        self._running = False
        if self.active_conn:
            self.active_conn.close()
        print("\nShutting down client...")

if __name__ == "__main__":
    client = TLSClient()
    client.run()