"""
Misure sperimentali di dimensioni e costi computazionali.
Eseguire con:  python -m voting.benchmark

Le prestazioni sono riportate come misura diretta: per ogni operazione si
indica il tempo totale impiegato per un numero fisso di esecuzioni e il
throughput (operazioni al secondo).
"""

import time
import json
import base64
import random
import tempfile

from cryptography.hazmat.primitives.serialization import Encoding

from . import pki
from . import crypto_utils as cu
from . import shamir
from . import merkle
from .segreteria import Segreteria
from .commissione import CommissioneElettorale, rebuild_private_key, result_message
from .ballot import encode_vote, decode_vote
from .ballot_record import record_bytes
from .netmsg import b64e


def bench(fn, iters):
    """Misura il tempo TOTALE (ms) per `iters` esecuzioni di `fn` e lo
    rapporta a una singola operazione."""
    t0 = time.perf_counter()
    for _ in range(iters):
        fn()
    total_ms = (time.perf_counter() - t0) * 1000.0
    per_op_ms = total_ms / iters
    return total_ms, per_op_ms


def row(name, fn, iters):
    total_ms, per_op_ms = bench(fn, iters)
    ops_s = (iters / total_ms * 1000.0) if total_ms > 0 else float("inf")
    print(f"  {name:<42} {total_ms:10.3f} {per_op_ms:10.4f} {ops_s:12.1f} {iters:6d}")


def main():
    pki_dir = tempfile.mkdtemp(prefix="voto_bench_")
    sa = Segreteria([f"s{i}" for i in range(200)], pki_dir, port=18443)

    # chiavi di esempio
    ce_key = cu.gen_rsa(2048)
    voter_key = cu.gen_rsa(2048)
    voter_cert = pki.issue_voter_cert(sa.ca_key, sa.ca_cert, voter_key.public_key(), "v")
    sa.publish_commitment("CE", cu.sha256(cu.pubkey_der(ce_key.public_key())))
    ce_cert = sa.sign_ce(ce_key.public_key())
    bb_key = cu.gen_rsa(2048)
    sa.publish_commitment("BB", cu.sha256(cu.pubkey_der(bb_key.public_key())))
    bb_cert = sa.sign_bb(bb_key.public_key())

    token = cu.sha256(cu.pubkey_der(voter_key.public_key()))
    pt = encode_vote(2, token)
    C = cu.oaep_encrypt(ce_key.public_key(), pt)
    msg = C + token + b"x" * 32 + b"1700000000.0"
    sigma_v = cu.pss_sign(voter_key, msg)

    #  DIMENSIONI
    print("\n=== DIMENSIONI DEI MESSAGGI (byte) ===")
    sizes = {
        "PKv (DER SubjectPublicKeyInfo)": len(cu.pubkey_der(voter_key.public_key())),
        "Cert(PKv) X.509 DER": len(voter_cert.public_bytes(Encoding.DER)),
        "Cert(PK_CE) X.509 DER": len(ce_cert.public_bytes(Encoding.DER)),
        "Cert(PK_BB) X.509 DER": len(bb_cert.public_bytes(Encoding.DER)),
        "token = SHA-256(PKv)": len(token),
        "nonce Ns (256 bit)": 32,
        "C = RSA-OAEP(PK_CE, v||token)": len(C),
        "sigma_v (RSA-PSS 2048)": len(sigma_v),
        "quota Shamir di p (~1024 bit)": (shamir.PRIME.bit_length() + 7) // 8,
    }
    for k, v in sizes.items():
        print(f"  {k:<42} {v:6d}")

    # record di scheda completo
    rec = {"C": b64e(C), "token": b64e(token), "sigma_v": b64e(sigma_v),
           "cert_pem": b64e(pki.cert_pem(voter_cert)),
           "Ns": b64e(b"x" * 32), "T": "1700000000.0",
           "sigma_bb": b64e(cu.pss_sign(bb_key, b"r"))}
    print(f"  {'record scheda B (byte canonici)':<42} {len(record_bytes(rec)):6d}")

    #  TEMPI
    # Colonne: tempo TOTALE (ms) per N esecuzioni | tempo per singola
    # operazione (ms) | throughput (op/s) | N esecuzioni.
    print("\n=== COSTO COMPUTAZIONALE ===")
    print(f"  {'operazione':<42} {'tot.(ms)':>10} {'op(ms)':>10} {'op/s':>12} {'iter':>6}")
    row("Keygen RSA-2048", lambda: cu.gen_rsa(2048), 10)
    row("OAEP encrypt (PK_CE)", lambda: cu.oaep_encrypt(ce_key.public_key(), pt), 100)
    row("OAEP decrypt (SK_CE)", lambda: cu.oaep_decrypt(ce_key, C), 100)
    row("PSS sign (RSA-2048)", lambda: cu.pss_sign(voter_key, msg), 100)
    row("PSS verify (RSA-2048)", lambda: cu.pss_verify(voter_key.public_key(), sigma_v, msg), 100)
    row("Cert sign (emissione X.509)",
        lambda: pki.issue_voter_cert(sa.ca_key, sa.ca_cert, voter_key.public_key(), "v"), 50)
    row("Cert verify (verify_signed_by)",
        lambda: pki.verify_signed_by(voter_cert, sa.ca_cert), 100)
    p = ce_key.private_numbers().p
    N = ce_key.public_key().public_numbers().n
    e = ce_key.public_key().public_numbers().e
    row("Shamir split (3,5) su p", lambda: shamir.split(p, 3, 5), 100)
    sh = shamir.split(p, 3, 5)[:3]
    row("Shamir reconstruct (3 quote)", lambda: shamir.reconstruct(sh), 100)
    row("Rebuild SK_CE da p", lambda: rebuild_private_key(shamir.reconstruct(sh), N, e), 20)

    # Merkle su N foglie
    for n in (10, 50, 100):
        leaves = [record_bytes(rec) for _ in range(n)]
        row(f"Merkle root ({n} schede)", lambda lv=leaves: merkle.merkle_root(lv), 50)

    #  SCRUTINIO PER SCHEDA
    print("\n=== SCRUTINIO: costo per scheda (verifica + decifratura) ===")
    print(f"  {'operazione':<42} {'tot.(ms)':>10} {'op(ms)':>10} {'op/s':>12} {'iter':>6}")
    def per_ballot():
        ok = (pki.verify_signed_by(voter_cert, sa.ca_cert)
              and cu.pss_verify(voter_key.public_key(), sigma_v, msg))
        v, tok = decode_vote(cu.oaep_decrypt(ce_key, C))
        return ok and v
    row("verifica+decifratura singola scheda", per_ballot, 100)

    #  PROIEZIONE A 10.000 STUDENTI 
    # Costi LATO SERVER, la generazione delle chiavi dei votanti è invece
    # distribuita: avviene una volta sul device di ciascuno studente.
    print("\n=== PROIEZIONE LATO SERVER A 10.000 STUDENTI ===")
    SCALE = 10_000

    # tempo per singola operazione, ricavato dal tempo totale misurato / iter
    _, t_issue = bench(
        lambda: pki.issue_voter_cert(sa.ca_key, sa.ca_cert,
                                     voter_key.public_key(), "v"), 50)
    def bb_verify_one():
        ok = pki.verify_signed_by(voter_cert, sa.ca_cert)
        _ = cu.sha256(cu.pubkey_der(voter_key.public_key()))
        ok = ok and cu.pss_verify(voter_key.public_key(), sigma_v, msg)
        return cu.pss_sign(bb_key, msg)         # sigma_BB
    _, t_cast = bench(bb_verify_one, 100)
    _, t_scrut = bench(per_ballot, 100)
    # radice di Merkle su 10.000 foglie (tempo totale misurato direttamente)
    big = [record_bytes(rec) for _ in range(SCALE)]
    merkle_total_ms, _ = bench(lambda: merkle.merkle_root(big), 3)

    reg_s = t_issue * SCALE / 1000
    cast_s = t_cast * SCALE / 1000
    scrut_s = t_scrut * SCALE / 1000
    print(f"  Registrazione (emissione 10.000 certificati)   ~ {reg_s:6.1f} s")
    print(f"  Votazione (verifica + sigma_BB di 10.000 schede)~ {cast_s:6.1f} s")
    print(f"  Scrutinio (verifica + decifratura 10.000 schede)~ {scrut_s:6.1f} s")
    print(f"  Radice di Merkle M_B su 10.000 schede            ~ {merkle_total_ms:6.1f} ms")
    print(f"  => elaborazione centrale totale (1 core)         ~ {reg_s+cast_s+scrut_s:6.1f} s")
    print( "     (parallelizzabile su piu' core/server; la votazione e'")
    print( "     inoltre distribuita nel tempo durante l'apertura delle urne)")

    print("\n(macchina di sviluppo; i valori assoluti dipendono dall'hardware)\n")


if __name__ == "__main__":
    main()