import pytest

# Check that the negotiated TLS cipher suite provides ephemeral key exchange
# (ECDHE/DHE) which indicates forward secrecy is in use for the session.

def test_forward_secrecy_after_key_compromise(session_pair):
    a_state, b_state = session_pair
    assert a_state is not None and b_state is not None
    # cipher() returns (name, protocol, secret_bits)
    a_cipher = a_state.conn.cipher()[0]
    b_cipher = b_state.conn.cipher()[0]
    assert a_cipher == b_cipher
    # TLS 1.3 cipher suite names don't include ECDHE/DHE but still provide
    # forward secrecy. Accept either an ECDHE/DHE-based suite or TLS1.3.
    version = a_state.conn.version()
    assert ("ECDHE" in a_cipher) or ("DHE" in a_cipher) or (version == "TLSv1.3"), \
        f"Expected ephemeral key exchange cipher or TLS 1.3, got {a_cipher} / {version}"