import pytest

def test_tls_send_receive_roundtrip(session_pair):
    """Simple smoke-test migrated to the `app` TLS API.

    Sends a plaintext over the negotiated TLS connection and verifies the
    peer receives the same bytes. This validates the handshake and basic I/O.
    """
    a_state, b_state = session_pair
    assert a_state is not None and b_state is not None

    # Use the underlying SSLSocket to write/read a single message.
    msg = b"hello world"
    # write from A -> B
    a_state.conn.write(msg)
    got = b_state.conn.read(4096)
    assert got == msg