from first_contact.channel import send, recv, IntegrityError
import pytest

def test_aead_tamper_fails_but_conn_policy_ok(session_pair):
    a_state, b_state = session_pair  # fixture that runs a full handshake and returns states
    ct = send(a_state, seq=1, plaintext=b"hello world")
    ct = bytearray(ct)
    ct[-1] ^= 1
    with pytest.raises(IntegrityError):
        recv(b_state, bytes(ct))