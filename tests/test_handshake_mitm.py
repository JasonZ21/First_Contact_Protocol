import pytest
from first_contact.handshake import initiate, respond, HandshakeError
from tests.utils.transport import InterceptingTransport, DROP

def test_handshake_aborts_on_ephemeral_key_swap(make_id_keys_factory, intercepting_pair):
    a_transport, b_transport = intercepting_pair
    pilot = make_id_keys_factory('Pilot')
    control = make_id_keys_factory('Control')

    # swap ephemeral pub in M2 (simple pattern matching assumed)
    def swap_m2(frame: bytes):
        # naive placeholder: detect 'M2' marker in frame bytes and mutate
        if b'M2' in frame:
            bframe = bytearray(frame)
            bframe[10:42] = b'\x00'*32  # force different ephemeral pub
            return bytes(bframe)
        return frame

    # apply script on receiving side of A such that it sees tampered M2
    a_transport.script('recv', swap_m2)

    with pytest.raises(HandshakeError):
        # call initiate which will use a_transport to talk to respond() used by the other end
        # In tests we might spawn thread to run respond(control, b_transport) or call in-process based on fixture.
        raise NotImplementedError("Test harness call to initiate/respond goes here")