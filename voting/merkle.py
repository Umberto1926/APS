"""
Albero di Merkle binario su SHA-256.

Usato in due punti del protocollo:
  - dal Bulletin Board per impegnarsi su tutte le schede depositate (radice M_B);
  - dalla Segreteria per impegnarsi sul log dei certificati emessi (radice M_C).

Ogni foglia e' l'hash di un record. Qualsiasi modifica, aggiunta o
rimozione cambia la radice ed e' quindi rilevabile. La prova di inclusione
permette a un elettore di dimostrare che la propria scheda e' nell'albero
in O(log N) hash.
"""

from .crypto_utils import sha256


def _leaf_hash(data: bytes) -> bytes:
    # Prefisso 0x00 per le foglie: separa il dominio foglie/nodi interni
    return sha256(b"\x00" + data)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right)


def merkle_root(records: list[bytes]) -> bytes:
    """Calcola la radice dell'albero a partire dai record (gia' in byte)."""
    if not records:
        return b"\x00" * 32
    level = [_leaf_hash(r) for r in records]
    while len(level) > 1:
        if len(level) % 2 == 1:          # numero dispari: si duplica l'ultimo
            level.append(level[-1])
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def inclusion_proof(records: list[bytes], index: int):
    """Restituisce la prova di inclusione (lista di (hash_fratello, is_right))
    per il record in posizione `index`."""
    level = [_leaf_hash(r) for r in records]
    proof = []
    idx = index
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        if idx % 2 == 0:                 # il nostro nodo e' a sinistra
            proof.append((level[idx + 1], True))   # fratello a destra
        else:                            # il nostro nodo e' a destra
            proof.append((level[idx - 1], False))  # fratello a sinistra
        idx //= 2
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
    return proof


def verify_proof(record: bytes, proof, root: bytes) -> bool:
    """Verifica che `record` sia incluso in un albero con radice `root`."""
    h = _leaf_hash(record)
    for sibling, sibling_on_right in proof:
        h = _node_hash(h, sibling) if sibling_on_right else _node_hash(sibling, h)
    return h == root
