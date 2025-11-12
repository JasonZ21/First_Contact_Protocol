import pytest
import importlib.util
import pathlib
import sys
import tempfile
import os
import shutil
import threading
import socket
import time as _time
import app.utils as app_utils
import app.handshake as app_handshake
from cryptography.hazmat.primitives import serialization
# Dynamically load helpers from tests/utils so pytest can import conftest
_utils_dir = pathlib.Path(__file__).parent / "utils"

def _load_util_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, str(_utils_dir / filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_ca = _load_util_module("tests_utils_ca", "ca.py")
_transport = _load_util_module("tests_utils_transport", "transport.py")
_timewrap = _load_util_module("tests_utils_timewrap", "timewrap.py")

make_root_ca = _ca.make_root_ca
make_id_keys = _ca.make_id_keys
DirectTransport = _transport.DirectTransport
InterceptingTransport = _transport.InterceptingTransport
timewarp = _timewrap.timewarp

# Ensure repository root is on sys.path so `app` package can be imported
repo_root = str(pathlib.Path(__file__).parent.parent)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

@pytest.fixture
def session_pair(request, make_id_keys_factory, root_ca):
    """Create in-process TLS client/server SessionState pair (a_state, b_state).

    This fixture generates temporary CA + identity cert files, points the
    `app.utils` paths at them, then spins up a server thread that accepts a
    single connection and returns the SessionState objects.
    """
    tmp = tempfile.mkdtemp(prefix="fcp_test_")
    try:
        ca_dir = os.path.join(tmp, "ca")
        keys_dir = os.path.join(tmp, "keys")
        os.makedirs(ca_dir, exist_ok=True)
        os.makedirs(keys_dir, exist_ok=True)

        # Create root CA and two identities
        root = root_ca
        a_keys = make_id_keys_factory("Alice", issuer=root)
        b_keys = make_id_keys_factory("Bob", issuer=root)

        # Write PEM files
        ca_pem = os.path.join(ca_dir, "root_cert.pem")
        with open(ca_pem, "wb") as f:
            f.write(root['cert'].public_bytes(serialization.Encoding.PEM))

        def write_keypair(name, pair):
            cert_p = os.path.join(keys_dir, f"{name}_cert.pem")
            key_p = os.path.join(keys_dir, f"{name}_key.pem")
            with open(cert_p, "wb") as f:
                f.write(pair['cert'].public_bytes(serialization.Encoding.PEM))
            with open(key_p, "wb") as f:
                f.write(pair['private_key'].private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            return cert_p, key_p

        a_cert_p, a_key_p = write_keypair("Alice", a_keys)
        b_cert_p, b_key_p = write_keypair("Bob", b_keys)

        # Prepare server thread
        server_ready = threading.Event()
        server_state = {}

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def server_thread():
            raw_conn, addr = listener.accept()
            # point app utils to server cert/key/ca
            app_utils.CA_ROOT_PATH = ca_pem
            app_utils.USER_CERT_PATH = b_cert_p
            app_utils.USER_KEY_PATH = b_key_p
            # create server SessionState
            state = app_handshake.handle_incoming_connection(raw_conn, addr)
            server_state['state'] = state
            server_ready.set()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        # Give server a moment to start listening
        _time.sleep(0.05)

        # point app utils to client cert/key/ca for the client side
        app_utils.CA_ROOT_PATH = ca_pem
        app_utils.USER_CERT_PATH = a_cert_p
        app_utils.USER_KEY_PATH = a_key_p

        # Initiate client connection
        a_state = app_handshake.initiate_tls_handshake("127.0.0.1", port)

        # Wait for server to accept and create state
        server_ready.wait(timeout=5.0)
        b_state = server_state.get('state')

        yield a_state, b_state

        # Teardown: close sockets
        try:
            if a_state and hasattr(a_state, 'conn'):
                a_state.conn.close()
        except Exception:
            pass
        try:
            if b_state and hasattr(b_state, 'conn'):
                b_state.conn.close()
        except Exception:
            pass
        listener.close()
    finally:
        shutil.rmtree(tmp)

@pytest.fixture(scope="session")
def root_ca():
    """Return a dict representing a root CA with signing key and certificate"""
    return make_root_ca("Test Root CA")

@pytest.fixture
def alt_root_ca():
    """Attacker root CA"""
    return make_root_ca("Attacker Root CA")

@pytest.fixture
def make_id_keys_factory(root_ca):
    def _make(name, issuer=root_ca, valid_days=30):
        return make_id_keys(name, issuer, valid_days=valid_days)
    return _make

@pytest.fixture
def direct_pair():
    """
    Return (transport_a, transport_b) connected; both are DirectTransport instances
    """
    a = DirectTransport()
    b = DirectTransport()
    a.attach_peer(b); b.attach_peer(a)
    return a, b

@pytest.fixture
def intercepting_pair():
    a = InterceptingTransport(); b = InterceptingTransport()
    a.attach_peer(b); b.attach_peer(a)
    return a, b

@pytest.fixture
def timewarp_ctx():
    return timewarp