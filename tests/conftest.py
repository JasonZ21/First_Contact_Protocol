import pytest
from .utils.ca import make_root_ca, make_id_keys
from .utils.transport import DirectTransport, InterceptingTransport
from .utils.timewarp import timewarp

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