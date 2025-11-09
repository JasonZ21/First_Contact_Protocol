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
    """Creates the SSL context, loading certificates and setting verification rules."""
    
    if is_server:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = False 

    # Load trusted CA root and user's identity chain
    context.load_verify_locations(CA_ROOT_PATH)
    context.load_cert_chain(certfile=USER_CERT_PATH, keyfile=USER_KEY_PATH)
    return context