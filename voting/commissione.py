"""
Commissione Elettorale (CE): generazione chiave di cifratura, condivisione
Shamir e scrutinio.

Setup:
  - genera (PK_CE, SK_CE) e ottiene Cert(PK_CE) dalla SA;
  - applica (t=3, n=5)-Threshold a un fattore primo p del modulo;
  - distribuisce le quote ai 5 commissari SU UN CANALE TLS SEPARATO per
    ciascuno ed ELIMINA SK_CE, p e il polinomio.

Scrutinio (a urne chiuse):
  - >= t commissari ricostruiscono p (Lagrange) -> q = N/p -> SK_CE;
  - scarica le schede dal BB, applica i controlli di validita';
  - per ogni token seleziona la scheda con T massimo (re-voting);
  - decifra, verifica token e v in [1,k], conteggia;
  - rimescola la lista dei voti aperti;
  - ogni commissario ri-deriva e FIRMA individualmente il risultato (sigma_Ci);
  - pubblica conteggi, lista rimescolata, firme, statistiche e M_B.
"""

import os
import ssl
import json
import math
import socket
import random
import threading

from cryptography.hazmat.primitives.asymmetric import rsa

from . import pki
from . import crypto_utils as cu
from . import shamir
from .ballot import decode_vote
from .ballot_record import record_bytes
from .netmsg import send_msg, recv_msg, tls_client_connect, b64e, b64d


# Messaggio canonico firmato dai commissari (counts || lista_rimescolata).
def result_message(counts: dict, shuffled: list) -> bytes:
    cb = b"".join(f"{k}:{counts[k]},".encode() for k in sorted(counts))
    return cb + b"|" + b",".join(str(v).encode() for v in shuffled)

def rebuild_private_key(p: int, N: int, e: int):
    """Ricostruisce SK_CE da p (e da N, e pubblici)."""
    q = N // p
    assert p * q == N, "fattore primo errato"
    d = pow(e, -1, math.lcm(p - 1, q - 1))
    for a, b in ((p, q), (q, p)):     # prova entrambi gli ordini p,q
        try:
            pub = rsa.RSAPublicNumbers(e, N)
            priv = rsa.RSAPrivateNumbers(
                a, b, d,
                rsa.rsa_crt_dmp1(d, a), rsa.rsa_crt_dmq1(d, b),
                rsa.rsa_crt_iqmp(a, b), pub)
            return priv.private_key()
        except ValueError:
            continue
    raise ValueError("impossibile ricostruire la chiave")


class Commissario:
    """Singolo commissario: detiene una quota Shamir e una chiave di firma.

    Il commissario apre un proprio endpoint TLS dedicato (certificato server firmato dalla SA) e
    riceve la propria quota dalla CE su una connessione TLS riservata,
    distinta da quella di ogni altro commissario.
    """

    def __init__(self, idx, sa, pki_dir):
        self.idx = idx
        self.host = "localhost"
        self.share = None                        # (i, g(i)), ricevuta su TLS
        self._sign_key = cu.gen_rsa(2048)        # (PK_Ci, SK_Ci) per la firma
        self.cert = sa.sign_commissioner(self._sign_key.public_key(), idx)

        # Endpoint TLS dedicato del commissario: chiave + certificato server
        # (SAN localhost, serverAuth) firmato dalla SA come gli altri server.
        self._tls_key = cu.gen_rsa(2048)
        tls_cert = pki.issue_server_cert(
            sa.ca_key, sa.ca_cert, self._tls_key.public_key(),
            f"Commissario {idx} - endpoint quota")
        self._key_path = os.path.join(pki_dir, f"commissario_{idx}_key.pem")
        self._cert_path = os.path.join(pki_dir, f"commissario_{idx}_cert.pem")
        with open(self._key_path, "wb") as f:
            f.write(cu.privkey_pem(self._tls_key))
        with open(self._cert_path, "wb") as f:
            f.write(pki.cert_pem(tls_cert))

        self.port = None
        self._server_sock = None
        self._thread = None
        self._running = False
        self._received = threading.Event()

    # Endpoint TLS per la ricezione della quota (attivo solo durante il setup)
    def start_share_endpoint(self):
        """Avvia il server TLS su una porta effimera dedicata e resta in
        attesa della propria quota dalla CE."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._cert_path, self._key_path)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((self.host, 0))                  # porta effimera dedicata
        self.port = raw.getsockname()[1]
        raw.listen(1)
        self._server_sock = ctx.wrap_socket(raw, server_side=True)
        self._server_sock.settimeout(1.0)
        self._running = True
        self._thread = threading.Thread(target=self._serve_once, daemon=True)
        self._thread.start()

    def _serve_once(self):
        # Una sola connessione utile: la consegna della quota da parte della CE.
        while self._running and not self._received.is_set():
            try:
                conn, _ = self._server_sock.accept()
            except (socket.timeout, ssl.SSLError):
                continue
            except OSError:
                break
            try:
                req = recv_msg(conn)
                if req.get("type") == "deliver_share":
                    i, yi = req["share"]
                    self.share = (int(i), int(yi))   # (i, g(i))
                    send_msg(conn, {"status": "share_received"})
                    self._received.set()
                else:
                    send_msg(conn, {"error": "richiesta sconosciuta"})
            except (ConnectionError, OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

    def stop_share_endpoint(self):
        """Chiude l'endpoint: il canale serve una sola volta, nel setup."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._server_sock:
            self._server_sock.close()

    def recount_and_sign(self, ballots_plain, counts, shuffled):
        """Il commissario ri-deriva il conteggio in autonomia; firma solo se
        coincide con quello proposto (un onesto rifiuta risultati incoerenti)."""
        my_counts = _count(ballots_plain, len(counts))
        if my_counts != counts:
            return None                          # rifiuto di firmare
        return cu.pss_sign(self._sign_key, result_message(counts, shuffled))


def _count(votes, k):
    return {str(j): sum(1 for v in votes if v == j) for j in range(1, k + 1)}


class CommissioneElettorale:
    def __init__(self, sa, k, t=3, n=5):
        self.k = k                               # numero di candidati
        self.t, self.n = t, n

        self._sa_host = sa.host
        self._sa_port = sa.port
        self._ca_cert_path = sa.ca_cert_path
        self._revoked_serials: set = set()
        
        # (1) coppia RSA per la cifratura dei voti
        ce_key = cu.gen_rsa(2048)
        nums = ce_key.private_numbers()
        self.N = ce_key.public_key().public_numbers().n
        self.e = ce_key.public_key().public_numbers().e
        self.public_key = ce_key.public_key()    # PK_CE (resta pubblica)

        # (2) pre-impegno sul registro istituzionale + certificato di PK_CE
        sa.publish_commitment("CE", cu.sha256(cu.pubkey_der(self.public_key)))
        self.cert = sa.sign_ce(self.public_key)

        # (3) Shamir (t,n) sul fattore primo p
        p = nums.p
        shares = shamir.split(p, t, n)

        # (4) commissari: ognuno con chiave di firma e proprio endpoint TLS
        ca_cert_path = sa.ca_cert_path
        self.commissari = [Commissario(i + 1, sa, sa.pki_dir) for i in range(n)]
        for c in self.commissari:
            c.start_share_endpoint()

        #      la CE consegna a CIASCUN commissario la propria quota su un
        #      canale TLS SEPARATO (una connessione TLS distinta per quota).
        #      Il client valida il certificato server del commissario
        try:
            for c, (i, yi) in zip(self.commissari, shares):
                s = tls_client_connect("localhost", c.port, ca_cert_path)
                try:
                    send_msg(s, {"type": "deliver_share", "share": [i, yi]})
                    r = recv_msg(s)
                    if r.get("status") != "share_received":
                        raise RuntimeError(
                            f"consegna quota fallita al commissario {c.idx}")
                finally:
                    s.close()
        finally:
            # il canale di distribuzione vive solo durante il setup
            for c in self.commissari:
                c.stop_share_endpoint()

        # (5) ELIMINA SK_CE, p, il polinomio e le quote in chiaro lato CE
        del ce_key, nums, p, shares

    def download_ballots(self, bb_host, bb_port, ca_cert_path):
        """Scarica le schede e M_B dal BB su canale TLS reale (§2.8).
        La CE valida il certificato del BB contro la Root CA out-of-band."""
        s = tls_client_connect(bb_host, bb_port, ca_cert_path)
        send_msg(s, {"type": "dump"})
        dump = recv_msg(s)
        s.close()
        return dump

    def scrutinio(self, bb_dump, ca_cert):
        """Esegue l'intero scrutinio e ritorna il payload pubblicato."""
        self.refresh_crl()
        # (a) ricostruzione della chiave con t quote
        used_shares = [c.share for c in self.commissari[:self.t]]
        p = shamir.reconstruct(used_shares)
        sk_ce = rebuild_private_key(p, self.N, self.e)

        ballots = bb_dump["ballots"]
        stats = {"ricevute": len(ballots), "non_valide": 0, "scartate_decifratura": 0}

        # (b) controlli di validita' su ciascuna scheda
        valid = []
        for b in ballots:
            cert = pki.load_cert_pem(b64d(b["cert_pem"]))
            pub = cert.public_key()
            token = b64d(b["token"]); C = b64d(b["C"])
            Ns = b64d(b["Ns"]); sigma_v = b64d(b["sigma_v"]); T = b["T"]
            ok = (pki.verify_signed_by(cert, ca_cert)
                  and not self.is_revoked(cert.serial_number)
                  and token == cu.sha256(cu.pubkey_der(pub))
                  and cu.pss_verify(pub, sigma_v, C + token + Ns + str(T).encode())
                  and cu.pss_verify(self._bb_pub(bb_dump, b),
                                    b64d(b["sigma_bb"]),
                                    C + token + Ns + str(T).encode() + sigma_v
                                    + b64d(b["cert_pem"])) and pki.is_cert_valid_now(cert))
            if ok:
                valid.append(b)
            else:
                stats["non_valide"] += 1

        # (c) per ogni token, scheda valida con T massimo (re-voting)
        latest = {}
        for b in valid:
            tk = b["token"]
            if tk not in latest or float(b["T"]) > float(latest[tk]["T"]):
                latest[tk] = b
        selected = list(latest.values())

        # (d) decifratura delle sole schede selezionate
        votes = []
        for b in selected:
            try:
                plain = cu.oaep_decrypt(sk_ce, b64d(b["C"]))
                v, tok_in = decode_vote(plain)
                if tok_in != b64d(b["token"]) or not (1 <= v <= self.k):
                    stats["scartate_decifratura"] += 1
                    continue
                votes.append(v)
            except Exception:
                stats["scartate_decifratura"] += 1

        # (e) conteggio + rimescolamento della lista dei voti aperti
        counts = _count(votes, self.k)
        shuffled = votes[:]
        random.shuffle(shuffled)

        # (f) ogni commissario ri-deriva e firma individualmente
        signatures = []
        for c in self.commissari[:self.t]:
            sig = c.recount_and_sign(votes, counts, shuffled)
            if sig is not None:
                signatures.append({"idx": c.idx, "cert_pem": b64e(pki.cert_pem(c.cert)),
                                   "sig": b64e(sig)})

        stats["valide"] = len(valid)
        stats["conteggiate"] = len(votes)

        # (g) elimina la chiave ricostruita
        del sk_ce, p

        return {
            "counts": counts,
            "shuffled": shuffled,
            "signatures": signatures,
            "stats": stats,
            "M_B": bb_dump["M_B"],
        }

    @staticmethod
    def _bb_pub(bb_dump, b):
        # Leggiamo direttamente il certificato dal dump (che è già bytes in base64)
        cert_bytes = b64d(bb_dump["bb_cert_pem"])
        return pki.load_cert_pem(cert_bytes).public_key()
    

    def refresh_crl(self):
            """Scarica la CRL firmata dalla SA via TLS e ne verifica la firma."""
            if self._sa_host is None:   # senza server TLS -> skip
                return
            s = tls_client_connect(self._sa_host, self._sa_port, self._ca_cert_path)
            try:
                send_msg(s, {"type": "get_crl"})
                crl = recv_msg(s)
            finally:
                s.close()
                
            body = ",".join(str(x) for x in sorted(crl["revoked"])).encode()
            
            with open(self._ca_cert_path, "rb") as f:
                ca_cert_bytes = f.read()
                
            if not cu.pss_verify(
                pki.load_cert_pem(ca_cert_bytes).public_key(),
                b64d(crl["sig"]),
                body,
            ):
                raise ValueError("CRL con firma non valida")
            self._revoked_serials = set(crl["revoked"])


    def is_revoked(self, serial: int) -> bool:
        return serial in self._revoked_serials