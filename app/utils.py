import os
import ssl

# --- CLI Color Codes ---
COLOR_ME = '\033[96m'      # Cyan for my outgoing messages
COLOR_PEER = '\033[92m'    # Green for incoming peer messages
COLOR_ERROR = '\033[91m'   # Red for errors
COLOR_SUCCESS = '\033[93m' # Yellow for success banner
COLOR_RESET = '\033[0m'    # Reset color

# --- Identity and File Paths ---
MY_USER_ID = os.environ.get("USER_ID", "Pilot-Alpha")
DEFAULT_PORT = 7000
LISTEN_TCP_PORT = int(os.environ.get("LISTEN_TCP_PORT", DEFAULT_PORT))

CA_ROOT_PATH = "ca/root_cert.pem"
USER_CERT_PATH = os.path.join("keys", f"{MY_USER_ID}_cert.pem")
USER_KEY_PATH = os.path.join("keys", f"{MY_USER_ID}_key.pem")

def get_common_name(subject_list):
    """Parses the certificate subject list to find and return the Common Name (CN)."""
    for entry in subject_list:
        for item in entry:
            if item[0] == 'commonName':
                return item[1]
    return 'Unknown'

def create_ssl_context(is_server=False):
    """Creates the SSL context with enhanced security settings.
    
    Args:
        is_server: Whether this context is for server-side or client-side
        
    Returns:
        Configured SSL context with mutual TLS authentication
        
    Raises:
        FileNotFoundError: If certificate files are not found
    """
    
    # Verify certificate files exist
    if not os.path.exists(CA_ROOT_PATH):
        raise FileNotFoundError(f"CA certificate not found: {CA_ROOT_PATH}")
    if not os.path.exists(USER_CERT_PATH):
        raise FileNotFoundError(f"User certificate not found: {USER_CERT_PATH}")
    if not os.path.exists(USER_KEY_PATH):
        raise FileNotFoundError(f"User key not found: {USER_KEY_PATH}")
    
    if is_server:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        # Disable hostname verification since we're using certificate CN for identity
        # In production, you might want to use subjectAltName instead
        context.check_hostname = False 

    # Enhanced security settings
    context.minimum_version = ssl.TLSVersion.TLSv1_2  # Minimum TLS 1.2
    
    # Prefer cipher suites with forward secrecy (ECDHE)
    # This provides perfect forward secrecy (PFS)
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
    
    # Load trusted CA root and user's identity chain
    context.load_verify_locations(CA_ROOT_PATH)
    context.load_cert_chain(certfile=USER_CERT_PATH, keyfile=USER_KEY_PATH)
    return context