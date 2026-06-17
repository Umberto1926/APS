"""
Casi di test: BULLETIN BOARD e COMMISSIONE ELETTORALE DISONESTI.
Ogni scenario manomette gli artefatti pubblicati e mostra che la verifica
universale (osservatore, sole chiavi pubbliche) lo RILEVA -> ESITO non valida,
oppure che lo schema a soglia lo RENDE IMPOSSIBILE.
"""
import os, time, copy, secrets, tempfile
from cryptography.hazmat.primitives.serialization import Encoding
from voting import pki, shamir, merkle
from voting import crypto_utils as cu
from voting.ballot import encode_vote
from voting.ballot_record import record_bytes
from voting.observer import verifica_universale
from voting.netmsg import b64e, b64d
from voting.commissione import (
    CommissioneElettorale, result_message, rebuild_private_key
)
K = 3   # Lista A/B/C

class FakeSA:
    """SA-stub: Root CA + log certificati + CRL (solo cio' che serve qui).
    Non avvia nessun server TLS: host/port sono None per segnalare
    alla CE di saltare refresh_crl (nessun server disponibile)."""
    def __init__(self, pki_dir, n_aventi):
        self.pki_dir = pki_dir
        self.host = None
        self.port = None
        self.ca_key, self.ca_cert = pki.create_root_ca()
        self.ca_cert_path = os.path.join(pki_dir, "root_ca.pem")
        open(self.ca_cert_path, "wb").write(pki.cert_pem(self.ca_cert))
        self.n_aventi = n_aventi
        self._cert_log = []
        self._revoked = set()
        self._commit = {}

    def publish_commitment(self, e, c): self._commit[e] = c
    def sign_ce(self, pub): return pki.issue_ce_cert(self.ca_key, self.ca_cert, pub)
    def sign_bb(self, pub): return pki.issue_bb_cert(self.ca_key, self.ca_cert, pub)
    def sign_commissioner(self, pub, idx):
        return pki.issue_commissioner_cert(self.ca_key, self.ca_cert, pub, idx)
    def issue_voter(self, pub, pseudo):
        cert = pki.issue_voter_cert(self.ca_key, self.ca_cert, pub, pseudo)
        self._cert_log.append(cert.public_bytes(Encoding.DER))
        return cert
    def revoke(self, serial): self._revoked.add(serial)
    def is_revoked(self, serial): return serial in self._revoked
    def cert_log(self):
        return {"certs": [b64e(d) for d in self._cert_log],
                "root": b64e(merkle.merkle_root(self._cert_log)),
                "n_aventi": self.n_aventi}


def craft_ballot(bb_key, bb_cert, voter_sk, voter_cert, ce_pub, v, T=None):
    """Riproduce cio' che un BB ONESTO fa: l'elettore firma sigma_v, il BB
    verifica e firma sigma_BB. Restituisce il record (campi base64)."""
    pub = voter_cert.public_key()
    token = cu.sha256(cu.pubkey_der(pub))
    C = cu.oaep_encrypt(ce_pub, encode_vote(v, token))
    Ns = secrets.token_bytes(32)
    T = T or f"{time.time():.6f}"
    cert_pem = pki.cert_pem(voter_cert)
    sigma_v = cu.pss_sign(voter_sk, C + token + Ns + T.encode())
    sigma_bb = cu.pss_sign(bb_key,
                           C + token + Ns + T.encode() + sigma_v + cert_pem)
    return {"C": b64e(C), "token": b64e(token), "sigma_v": b64e(sigma_v),
            "cert_pem": b64e(cert_pem), "Ns": b64e(Ns), "T": T,
            "sigma_bb": b64e(sigma_bb)}


def make_dump(ballots, bb_key, bb_cert):
    """Costruisce il dump del BB con radice Merkle ricalcolata."""
    leaves = [record_bytes(b) for b in ballots]
    return {"ballots": ballots,
            "M_B": b64e(merkle.merkle_root(leaves)),
            "bb_cert_pem": b64e(pki.cert_pem(bb_cert))}


def line(name, key, report, expect_false):
    val = report.get(key)
    flagged = (val is False)
    ok = (flagged == expect_false)
    esito = report["ESITO"]
    tag = "PASS" if (ok and esito is False) else "FAIL"
    print(f"  [{tag}] {name:<50} {key}={val}  ESITO={esito}")
    return ok and esito is False


def main():
    d = tempfile.mkdtemp(prefix="voto_dis_")
    sa = FakeSA(d, n_aventi=10)

    #  CE reale (PK_CE + commissari con quote distribuite su TLS) 
    ce = CommissioneElettorale(sa, k=K)
    ce_pub = ce.public_key          # i voti si cifrano con PK_CE

    # identita' del BB 
    bb_key = cu.gen_rsa(2048)
    sa.publish_commitment("BB", cu.sha256(cu.pubkey_der(bb_key.public_key())))
    bb_cert = sa.sign_bb(bb_key.public_key())

    # 6 elettori onesti, certificati emessi e loggati dalla SA 
    voters = []
    votes_plain = [1, 2, 3, 1, 2, 3]
    for i, v in enumerate(votes_plain):
        sk = cu.gen_rsa(2048)
        cert = sa.issue_voter(sk.public_key(), f"voter-{i}")
        voters.append((sk, cert, v))

    # registro ONESTO del BB 
    ballots = [craft_ballot(bb_key, bb_cert, sk, cert, ce_pub, v)
               for sk, cert, v in voters]
    dump = make_dump(ballots, bb_key, bb_cert)

    #  scrutinio ONESTO (decifratura reale, t firme) 
    # refresh_crl 
    result = ce.scrutinio(dump, sa.ca_cert)
    cert_log = sa.cert_log()

    base = verifica_universale(dump, result, cert_log,
                               sa.ca_cert, sa.is_revoked, K)
    print("BASELINE (tutto onesto):  ESITO =", base["ESITO"],
          " counts =", result["counts"],
          " firme =", len(result["signatures"]))
    assert base["ESITO"] is True, "la baseline onesta deve essere VALIDA"

    allok = True

    print("\n=== BULLETIN BOARD DISONESTO (TM9 / TM6) ===")

    # BB-1: inietta una scheda FALSA con sigma_v inventata
    # Il BB puo' ricalcolare M_B sul set alterato, ma sigma_v non verifica.
    bs = copy.deepcopy(ballots)
    sk_x, cert_x, _ = voters[0]
    fake = craft_ballot(bb_key, bb_cert, sk_x, cert_x, ce_pub, 1)
    fake["sigma_v"] = b64e(secrets.token_bytes(256))
    bs.append(fake)
    dump_bad = make_dump(bs, bb_key, bb_cert)
    r = verifica_universale(dump_bad, result, cert_log,
                            sa.ca_cert, sa.is_revoked, K)
    allok &= line("BB inietta scheda falsa (sigma_v inventata)",
                  "firme_elettore_valide", r, True)

    # BB-2: altera una scheda GIA' DEPOSITATA senza poter cambiare M_B
    # (M_B e' gia' stata pubblicata e firmata dalla CE).
    bs = copy.deepcopy(ballots)
    raw = bytearray(b64d(bs[0]["C"])); raw[0] ^= 0x01
    bs[0]["C"] = b64e(bytes(raw))
    dump_bad = {"ballots": bs,
                "M_B": dump["M_B"],          # M_B originale inalterata
                "bb_cert_pem": dump["bb_cert_pem"]}
    r = verifica_universale(dump_bad, result, cert_log,
                            sa.ca_cert, sa.is_revoked, K)
    allok &= line("BB altera scheda con M_B gia' pubblicata",
                  "radice_M_B_coerente", r, True)

    # BB-3: duplica la coppia (token, C) per saturare il contatore re-voting
    # e far contare due volte lo stesso voto.
    bs = copy.deepcopy(ballots)
    bs.append(copy.deepcopy(bs[0]))          # copia esatta -> stessa coppia
    dump_bad = make_dump(bs, bb_key, bb_cert)
    r = verifica_universale(dump_bad, result, cert_log,
                            sa.ca_cert, sa.is_revoked, K)
    allok &= line("BB duplica coppia (token,C) per doppio conteggio",
                  "nessuna_coppia_token_C_ripetuta", r, True)

    # BB-4: BB disonesto forgia sigma_BB per una scheda mai presentata
    # dall'elettore (sigma_v corretta perche' usa la chiave vera del voter,
    # ma il BB la inserisce senza che l'elettore l'abbia inviata).
    bs = copy.deepcopy(ballots)
    sk_x, cert_x, _ = voters[1]
    forged = craft_ballot(bb_key, bb_cert, sk_x, cert_x, ce_pub, 2)
    # Usiamo un Ns diverso -> sigma_v non coincide piu' con nonce registrato,
    # ma la verifica universale controlla sigma_v indipendentemente.
    forged["Ns"] = b64e(secrets.token_bytes(32))   # Ns diverso da quello firmato
    # Ricalcola sigma_bb coerente con il Ns falso (il BB puo' farlo):
    C = b64d(forged["C"]); token = b64d(forged["token"])
    Ns_new = b64d(forged["Ns"]); T = forged["T"]
    sigma_v_orig = b64d(forged["sigma_v"])
    cert_pem = b64d(forged["cert_pem"])
    sigma_bb_new = cu.pss_sign(bb_key,
                               C + token + Ns_new + T.encode()
                               + sigma_v_orig + cert_pem)
    forged["sigma_bb"] = b64e(sigma_bb_new)
    bs.append(forged)
    dump_bad = make_dump(bs, bb_key, bb_cert)
    r = verifica_universale(dump_bad, result, cert_log,
                            sa.ca_cert, sa.is_revoked, K)
    allok &= line("BB forgia sigma_BB con Ns alterato (sigma_v non torna)",
                  "firme_elettore_valide", r, True)

    # ================================================================
    print("\n=== COMMISSIONE ELETTORALE DISONESTA (TM2) ===")

    # CE-1: pubblica counts falsi (incoerenti con shuffled e firme)
    res_bad = copy.deepcopy(result)
    res_bad["counts"] = dict(res_bad["counts"])
    res_bad["counts"]["1"] += 5
    r = verifica_universale(dump, res_bad, cert_log,
                            sa.ca_cert, sa.is_revoked, K)
    allok &= line("CE pubblica counts gonfiati (firme non tornano)",
                  "riconteggio_coerente", r, True)

    # CE-2: meno di t firme (un commissario onesto si rifiuta di firmare
    # un risultato che non riesce a verificare).
    res_bad = copy.deepcopy(result)
    res_bad["signatures"] = res_bad["signatures"][:2]   # 2 < t=3
    r = verifica_universale(dump, res_bad, cert_log,
                            sa.ca_cert, sa.is_revoked, K)
    allok &= line("CE presenta meno di t firme dei commissari",
                  "almeno_t_firme_commissari", r, True)

    # CE-3: i t commissari COLLUDONO e firmano un tally gonfiato
    # internamente coerente (counts == recount(shuffled), t firme valide),
    # ma con un voto fantasma non presente in nessuna scheda valida del BB.
    inflated_shuffled = list(result["shuffled"]) + [1]
    inflated_counts = {str(j): sum(1 for v in inflated_shuffled if v == j)
                       for j in range(1, K + 1)}
    msg = result_message(inflated_counts, inflated_shuffled)
    forged_sigs = []
    for c in ce.commissari[:ce.t]:
        forged_sigs.append({
            "idx": c.idx,
            "cert_pem": b64e(pki.cert_pem(c.cert)),
            "sig": b64e(cu.pss_sign(c._sign_key, msg))
        })
    res_bad = {"counts": inflated_counts, "shuffled": inflated_shuffled,
               "signatures": forged_sigs, "M_B": result["M_B"]}
    r = verifica_universale(dump, res_bad, cert_log,
                            sa.ca_cert, sa.is_revoked, K)
    print(f"    (riconteggio_coerente={r['riconteggio_coerente']}, "
          f"almeno_t_firme={r['almeno_t_firme_commissari']})")
    allok &= line("CE collusion: tally gonfiato con t firme valide",
                  "n_voti_coerente_con_schede_valide", r, True)

    # CE-4: sotto soglia -> impossibile ricostruire la chiave (segretezza)
    try:
        wrong_p = shamir.reconstruct([c.share for c in ce.commissari[:2]])
        bad_key = rebuild_private_key(wrong_p, ce.N, ce.e)
        from voting import crypto_utils as cu2
        known_C = b64d(ballots[0]["C"])
        cu2.oaep_decrypt(bad_key, known_C)
        thr_ok = False
    except Exception:
        thr_ok = True
    print(f"  [{'PASS' if thr_ok else 'FAIL'}] CE sotto-soglia (2 < t=3 quote): "
        f"chiave NON ricostruibile")
    allok &= thr_ok

    
    print("\n" + "=" * 60)
    print("RISULTATO FINALE:",
          "TUTTI GLI ATTACCHI RILEVATI/IMPEDITI" if allok else "QUALCOSA NON VA")


if __name__ == "__main__":
    main()