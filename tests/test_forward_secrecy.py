def test_forward_secrecy_after_key_compromise(session_pair):
    a_state, b_state = session_pair
    # send some messages
    # then "compromise" identity key (simulate by exposing it)
    # derive what attacker could compute and assert they cannot decrypt earlier ciphertexts
    raise NotImplementedError