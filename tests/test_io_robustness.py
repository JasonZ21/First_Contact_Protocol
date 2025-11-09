import threading
import time
import pytest

from app.channel import recv_loop


def test_recv_loop_handles_abrupt_close(session_pair):
    """Start a recv_loop on the responder side, have the initiator send a
    message and then close abruptly. recv_loop should detect disconnect and
    call the on_disconnect callback.
    """
    a_state, b_state = session_pair
    assert a_state is not None and b_state is not None

    disconnected = threading.Event()

    def on_disconnect():
        disconnected.set()

    # run recv_loop in a thread reading from B's connection
    rt = threading.Thread(target=recv_loop, args=(b_state.conn, 'peer', on_disconnect), daemon=True)
    rt.start()

    # Give thread a moment to start
    time.sleep(0.05)

    # A sends a message then closes connection abruptly
    a_state.conn.write(b"hello-abrupt")
    a_state.conn.close()

    # Wait for recv_loop to detect disconnect
    assert disconnected.wait(timeout=2.0), "recv_loop did not detect disconnect"


def test_large_message_handling(session_pair):
    """Send a large payload from A to B and ensure recv on the socket reads
    the entire payload (this exercises the underlying SSL read handling).
    """
    a_state, b_state = session_pair
    assert a_state is not None and b_state is not None

    # create a large payload (~128 KB)
    payload = b"X" * (128 * 1024)

    # write from A -> B
    a_state.conn.write(payload)

    # read repeatedly until we've collected full payload
    collected = bytearray()
    while len(collected) < len(payload):
        chunk = b_state.conn.read(16384)
        if not chunk:
            break
        collected.extend(chunk)

    assert bytes(collected) == payload