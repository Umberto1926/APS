"""
+Codifica del voto e struttura della scheda.

La preferenza e' un intero v in [1, k].
Dentro il ciphertext il voto e' legato al token pseudonimo:

    plaintext = v (2 byte big-endian) || token (32 byte SHA-256)
    C = RSA-OAEP(PK_CE, plaintext)

Il legame v||token previene la copia di scheda: in scrutinio la CE
controlla che il token estratto dal ciphertext coincida con il token in
chiaro della scheda.
"""


def encode_vote(v: int, token: bytes) -> bytes:
    """v in [1,k] su 2 byte, seguito dal token a 32 byte."""
    assert 0 < v < 65536
    assert len(token) == 32
    return v.to_bytes(2, "big") + token


def decode_vote(plaintext: bytes):
    """Inverso di encode_vote: ritorna (v, token)."""
    v = int.from_bytes(plaintext[:2], "big")
    token = plaintext[2:34]
    return v, token
