"""

Serializzazione canonica del record di scheda B depositato sul BB:

    B = (C, token, sigma_v, Cert(PKv), Ns, T, sigma_BB)

La foglia di Merkle e' SHA-256(B). BB, elettore (verifica individuale) e
osservatore (verifica universale) devono ottenere gli stessi byte: per
questo la concatenazione segue un ordine fisso.
"""

from .netmsg import b64d


# Ordine canonico dei campi nel record (deve essere identico ovunque).
def record_bytes(b: dict) -> bytes:
    return (
        b64d(b["C"])
        + b64d(b["token"])
        + b64d(b["sigma_v"])
        + b64d(b["cert_pem"])
        + b64d(b["Ns"])
        + str(b["T"]).encode()
        + b64d(b["sigma_bb"])
    )
