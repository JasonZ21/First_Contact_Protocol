import os
import json
import hashlib
from typing import List

LOG_PATH = os.path.join("ca", "merkle_log.json")


def _load_log() -> dict:
    if not os.path.exists(LOG_PATH):
        return {"leaves": [], "root": None}
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_log(data: dict):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _compute_root(leaves: List[str]) -> str:
    if not leaves:
        return None
    nodes = leaves[:]
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i+1] if i+1 < len(nodes) else nodes[i]
            combined = (left + right).encode()
            next_level.append(_hash(combined))
        nodes = next_level
    return nodes[0]


def append_cert(cert_pem: bytes) -> dict:
    """Appends cert PEM to the log. Returns metadata including index and new root."""
    ob = _load_log()
    leaf = _hash(cert_pem)
    ob.setdefault("leaves", []).append(leaf)
    ob["root"] = _compute_root(ob["leaves"]) if ob["leaves"] else None
    _save_log(ob)
    return {"index": len(ob["leaves"])-1, "root": ob["root"]}


def get_root() -> str:
    return _load_log().get("root")


def get_leaves() -> List[str]:
    return _load_log().get("leaves", [])
