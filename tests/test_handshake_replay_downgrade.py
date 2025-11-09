import tempfile
import threading
import socket
import os
import time
import pytest
from cryptography.hazmat.primitives import serialization

import app.utils as app_utils
import app.handshake as app_handshake


def _write_pair(tmpdir, name, pair):
    cert_p = os.path.join(tmpdir, f"{name}_cert.pem")
    key_p = os.path.join(tmpdir, f"{name}_key.pem")
    with open(cert_p, "wb") as f:
        f.write(pair['cert'].public_bytes(serialization.Encoding.PEM))
    with open(key_p, "wb") as f:
        f.write(pair['private_key'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    return cert_p, key_p


def test_truncation_early_close(make_id_keys_factory, root_ca):
    """Server sends a short payload after handshake and then closes; client
    should receive the payload and then subsequent reads show EOF/empty.
    """
    tmp = tempfile.mkdtemp(prefix="fcp_trunc_")
    try:
        ca_pem = os.path.join(tmp, "root_cert.pem")
        with open(ca_pem, "wb") as f:
            f.write(root_ca['cert'].public_bytes(serialization.Encoding.PEM))

        a_keys = make_id_keys_factory("Alice", issuer=root_ca)
        s_keys = make_id_keys_factory("Server", issuer=root_ca)
        a_cert, a_key = _write_pair(tmp, "a", a_keys)
        s_cert, s_key = _write_pair(tmp, "s", s_keys)

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def server_thread():
            raw_conn, addr = listener.accept()
            # server uses its cert/key
            app_utils.CA_ROOT_PATH = ca_pem
            app_utils.USER_CERT_PATH = s_cert
            app_utils.USER_KEY_PATH = s_key
            ctx = app_handshake.create_ssl_context(is_server=True)
            ssl_conn = ctx.wrap_socket(raw_conn, server_side=True)
            # After handshake, send a short payload then close abruptly
            try:
                ssl_conn.send(b"partial-message")
            finally:
                ssl_conn.close()

        t = threading.Thread(target=server_thread, daemon=True)
        t.start()

        # client uses its cert and trusts CA
        app_utils.CA_ROOT_PATH = ca_pem
        app_utils.USER_CERT_PATH = a_cert
        app_utils.USER_KEY_PATH = a_key

        a_state = app_handshake.initiate_tls_handshake("127.0.0.1", port)
        assert a_state is not None
        # read first payload
        data = a_state.conn.read(4096)
        assert data == b"partial-message"
        # next read should be empty (EOF) or raise; accept empty bytes
        try:
            more = a_state.conn.read(4096)
        except Exception:
            more = b""
        assert more == b""

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


def test_replay_server_handshake_fails(make_id_keys_factory, root_ca):
    """Record server->client handshake bytes from a real TLS server then
    replay them to a fresh client (without contacting the real server). The
    client should fail the handshake when it receives replayed messages.
    """
    tmp = tempfile.mkdtemp(prefix="fcp_replay_")
    try:
        ca_pem = os.path.join(tmp, "root_cert.pem")
        with open(ca_pem, "wb") as f:
            f.write(root_ca['cert'].public_bytes(serialization.Encoding.PEM))

        server_keys = make_id_keys_factory("Server", issuer=root_ca)
        client_keys = make_id_keys_factory("Client", issuer=root_ca)
        s_cert, s_key = _write_pair(tmp, "s", server_keys)
        c_cert, c_key = _write_pair(tmp, "c", client_keys)

        # Real server
        real_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        real_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        real_listener.bind(("127.0.0.1", 0))
        real_listener.listen(1)
        real_port = real_listener.getsockname()[1]

        server_ready = threading.Event()

        def real_server():
            raw_conn, addr = real_listener.accept()
            app_utils.CA_ROOT_PATH = ca_pem
            app_utils.USER_CERT_PATH = s_cert
            app_utils.USER_KEY_PATH = s_key
            ctx = app_handshake.create_ssl_context(is_server=True)
            ssl_conn = ctx.wrap_socket(raw_conn, server_side=True)
            # keep server alive briefly to complete handshake
            server_ready.set()
            time.sleep(0.5)
            ssl_conn.close()

        rs = threading.Thread(target=real_server, daemon=True)
        rs.start()

        # Proxy: connect to real server and record server->client bytes
        record = bytearray()

        proxy_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        proxy_listener.bind(("127.0.0.1", 0))
        proxy_listener.listen(1)
        proxy_port = proxy_listener.getsockname()[1]

        def proxy_first_connection():
            # accept client, connect to real server and relay while recording server->client
            prox_conn, _ = proxy_listener.accept()
            server_sock = socket.create_connection(("127.0.0.1", real_port))
            # simple byte relay until server_ready
            server_sock.settimeout(1.0)
            prox_conn.settimeout(1.0)
            try:
                while not server_ready.is_set():
                    time.sleep(0.01)
                # relay for a short window and record
                end = time.time() + 0.5
                while time.time() < end:
                    try:
                        data = server_sock.recv(4096)
                        if data:
                            # forward to client and record
                            prox_conn.sendall(data)
                            record.extend(data)
                        # forward any client->server bytes too
                        try:
                            c2s = prox_conn.recv(4096)
                            if c2s:
                                server_sock.sendall(c2s)
                        except socket.timeout:
                            pass
                    except socket.timeout:
                        pass
            finally:
                try:
                    server_sock.close()
                except Exception:
                    pass
                try:
                    prox_conn.close()
                except Exception:
                    pass

        p_thread = threading.Thread(target=proxy_first_connection, daemon=True)
        p_thread.start()

        # Client connects to proxy (first connection) to trigger recording
        app_utils.CA_ROOT_PATH = ca_pem
        app_utils.USER_CERT_PATH = c_cert
        app_utils.USER_KEY_PATH = c_key
        try:
            s = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
            # wrap as client TLS to perform handshake via proxy
            ctx = app_handshake.create_ssl_context(is_server=False)
            ssl_s = ctx.wrap_socket(s, server_hostname="127.0.0.1")
            # if handshake succeeded, close
            ssl_s.close()
        except Exception:
            # ignore; recording may still have happened
            pass

        time.sleep(0.1)

        # Now second client connects to proxy; proxy will immediately send recorded server bytes
        def proxy_replay():
            c, _ = proxy_listener.accept()
            try:
                if record:
                    c.sendall(bytes(record))
            finally:
                c.close()

        pr = threading.Thread(target=proxy_replay, daemon=True)
        pr.start()

        # New client attempts handshake against proxy replay
        app_utils.CA_ROOT_PATH = ca_pem
        app_utils.USER_CERT_PATH = c_cert
        app_utils.USER_KEY_PATH = c_key
        try:
            s2 = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
            ctx2 = app_handshake.create_ssl_context(is_server=False)
            # Wrapping should raise or fail because bytes are out-of-context
            with pytest.raises(Exception):
                ctx2.wrap_socket(s2, server_hostname="127.0.0.1")
        finally:
            try:
                s2.close()
            except Exception:
                pass

    finally:
        try:
            real_listener.close()
        except Exception:
            pass
        try:
            proxy_listener.close()
        except Exception:
            pass
        try:
            os.rmdir(tmp)
        except Exception:
            pass