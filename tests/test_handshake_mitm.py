import pytest
import tempfile
import threading
import socket
import os
from cryptography.hazmat.primitives import serialization

import app.utils as app_utils
import app.handshake as app_handshake


def test_handshake_fails_with_untrusted_server_cert(make_id_keys_factory, root_ca, alt_root_ca):
    """If the server presents a cert signed by an attacker CA, the client
    should fail certificate verification and the handshake should not succeed.
    """
    tmp = tempfile.mkdtemp(prefix="fcp_mitm_")
    try:
        ca_pem = os.path.join(tmp, "root_cert.pem")
        # Client identity (trusted by root_ca)
        a_keys = make_id_keys_factory("Alice", issuer=root_ca)
        # Server identity signed by attacker CA (untrusted by client)
        bad_server = make_id_keys_factory("Eve", issuer=alt_root_ca)

        with open(ca_pem, "wb") as f:
            f.write(root_ca['cert'].public_bytes(serialization.Encoding.PEM))

        # write client cert/key
        a_cert = os.path.join(tmp, "a_cert.pem")
        a_key = os.path.join(tmp, "a_key.pem")
        with open(a_cert, "wb") as f:
            f.write(a_keys['cert'].public_bytes(serialization.Encoding.PEM))
        with open(a_key, "wb") as f:
            f.write(a_keys['private_key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # write bad server cert/key
        s_cert = os.path.join(tmp, "s_cert.pem")
        s_key = os.path.join(tmp, "s_key.pem")
        with open(s_cert, "wb") as f:
            f.write(bad_server['cert'].public_bytes(serialization.Encoding.PEM))
        with open(s_key, "wb") as f:
            f.write(bad_server['private_key'].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Start server that uses the attacker-signed cert
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        server_err = {}

        def server_thread():
            try:
                raw_conn, addr = listener.accept()
                app_utils.CA_ROOT_PATH = s_cert  # server's view of CA not relevant
                app_utils.USER_CERT_PATH = s_cert
                app_utils.USER_KEY_PATH = s_key
                app_handshake.handle_incoming_connection(raw_conn, addr)
            except Exception as e:
                server_err['exc'] = e

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        # Client uses trusted root CA and its own cert
        app_utils.CA_ROOT_PATH = ca_pem
        app_utils.USER_CERT_PATH = a_cert
        app_utils.USER_KEY_PATH = a_key

        # Monkeypatch create_ssl_context in the handshake module so the test
        # uses a context that trusts only the CA file we provided (avoids any
        # system CA influence).
        import ssl as _ssl

        def _test_create_ssl_context(is_server: bool = False):
            ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER if is_server else _ssl.PROTOCOL_TLS_CLIENT)
            ctx.verify_mode = _ssl.CERT_REQUIRED
            if not is_server:
                ctx.check_hostname = False
            ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
            ctx.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5')
            # Use the paths currently set on app_utils
            ctx.load_verify_locations(cafile=app_utils.CA_ROOT_PATH)
            ctx.load_cert_chain(certfile=app_utils.USER_CERT_PATH, keyfile=app_utils.USER_KEY_PATH)
            return ctx

        # apply monkeypatch (both client and server use the same function via app_handshake)
        app_handshake.create_ssl_context = _test_create_ssl_context

        a_state = app_handshake.initiate_tls_handshake("127.0.0.1", port)

        # Client handshake should fail (None) because server cert is untrusted
        assert a_state is None

    finally:
        try:
            listener.close()
        except Exception:
            pass
        try:
            os.remove(ca_pem)
        except Exception:
            pass
        try:
            os.remove(a_cert); os.remove(a_key)
        except Exception:
            pass
        try:
            os.remove(s_cert); os.remove(s_key)
        except Exception:
            pass
        try:
            os.rmdir(tmp)
        except Exception:
            pass