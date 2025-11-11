import json
import os
import datetime
from typing import List
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

CRL_PATH = os.path.join("ca", "crl.json")
CRL_SIG_PATH = os.path.join("ca", "crl.sig")
CA_KEY_PATH = os.path.join("ca", "root_key.pem")


def _load_raw_crl() -> dict:
    if not os.path.exists(CRL_PATH):
        return {"revoked": [], "updated_at": None}
    with open(CRL_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_raw_crl(data: dict):
    os.makedirs(os.path.dirname(CRL_PATH), exist_ok=True)
    with open(CRL_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)


def sign_crl():
    """Signs the CRL JSON and writes signature to CRL_SIG_PATH."""
    if not os.path.exists(CA_KEY_PATH):
        raise FileNotFoundError("CA private key not found for CRL signing")
    raw = json.dumps(_load_raw_crl(), sort_keys=True).encode("utf-8")
    with open(CA_KEY_PATH, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    sig = key.sign(raw, padding.PKCS1v15(), hashes.SHA256())
    with open(CRL_SIG_PATH, "wb") as f:
        f.write(sig)


def verify_crl_signature(ca_pubkey) -> bool:
    """Verify CRL signature given CA public key object."""
    if not os.path.exists(CRL_SIG_PATH):
        return False
    raw = json.dumps(_load_raw_crl(), sort_keys=True).encode("utf-8")
    with open(CRL_SIG_PATH, "rb") as f:
        sig = f.read()
    try:
        ca_pubkey.verify(sig, raw, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def revoke(serial: int, reason: str = "unspecified"):
    data = _load_raw_crl()
    now = datetime.datetime.utcnow().isoformat() + "Z"
    # avoid duplicate
    if any(int(x.get("serial")) == int(serial) for x in data.get("revoked", [])):
        return False
    data.setdefault("revoked", []).append({"serial": int(serial), "revoked_at": now, "reason": reason})
    data["updated_at"] = now
    _save_raw_crl(data)
    sign_crl()
    return True


def get_revoked_serials() -> List[int]:
    data = _load_raw_crl()
    return [int(x.get("serial")) for x in data.get("revoked", [])]


def is_revoked(serial: int) -> bool:
    return int(serial) in get_revoked_serials()
