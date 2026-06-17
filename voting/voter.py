"""
Elettore (studente): client del protocollo.

Flusso:
  - genera (PKv, SKv) e registra l'authenticator FIDO2 presso la SA;
  - REGISTRAZIONE: si autentica via FIDO2 su TLS e ottiene Cert(PKv) ;
  - VOTAZIONE: verifica Cert(PK_CE), apre la sessione col BB, cifra e firma
    la scheda e la trasmette su TLS; conserva C e la ricevuta sigma_BB;
  - VERIFICA INDIVIDUALE: ritrova la propria scheda sul BB e ne controlla
    firma, ciphertext e inclusione nell'albero di Merkle.
"""

import time

from . import pki
from . import crypto_utils as cu
from . import merkle
from .ballot import encode_vote
from .ballot_record import record_bytes
from .fido2_auth import Authenticator
from .netmsg import send_msg, recv_msg, tls_client_connect, b64e, b64d

# Cache del certificato della Root CA (PK_CA) per path, per evitare riletture.
_CA_CACHE = {}


def _load_ca(ca_cert_path):
    ca = _CA_CACHE.get(ca_cert_path)
    if ca is None:
        with open(ca_cert_path, "rb") as f:
            ca = pki.load_cert_pem(f.read())
        _CA_CACHE[ca_cert_path] = ca
    return ca


class Voter:
    def __init__(self, student_id):
        self.student_id = student_id
        self._sk = cu.gen_rsa(2048)              # SKv (privata, non lascia il device)
        self.pk = self._sk.public_key()          # PKv
        self.token = cu.sha256(cu.pubkey_der(self.pk))
        self.authenticator = Authenticator()     # FIDO2
        self.cert = None                         # Cert(PKv), assegnato in registrazione
        self.cert_pem = None
        self._local_C = None                     # ciphertext conservato per la verifica
        self._receipt = None                     # record completo (con sigma_BB)

    def enroll_fido(self, sa_host, sa_port, ca_cert_path):
        """Enrollment FIDO2 su TLS reale: richiede una challenge di
        registrazione, genera la coppia (PK_FIDO, SK_FIDO) e prova il
        possesso di SK_FIDO firmando l'attestazione."""
        s = tls_client_connect(sa_host, sa_port, ca_cert_path)
        try:
            send_msg(s, {"type": "enroll_challenge", "student_id": self.student_id})
            r = recv_msg(s)
            if "error" in r:
                return False, r["error"]
            challenge = b64d(r["challenge"])
            pk_fido = self.authenticator.make_credential()
            attestation = self.authenticator.attest(challenge, "segreteria.ateneo.it")
            send_msg(s, {"type": "enroll", "student_id": self.student_id,
                         "pubkey_der": b64e(cu.pubkey_der(pk_fido)),
                         "attestation": b64e(attestation)})
            r = recv_msg(s)
        finally:
            s.close()
        if "error" in r:
            return False, r["error"]
        return True, "enrolled"

    def register(self, sa_host, sa_port, ca_cert_path):
        """Autenticazione FIDO2 + emissione di Cert(PKv) su un'unica
        sessione TLS (challenge -> response -> certificato)."""
        s = tls_client_connect(sa_host, sa_port, ca_cert_path)
        try:
            # 1) richiede la challenge
            send_msg(s, {"type": "fido_challenge", "student_id": self.student_id})
            r = recv_msg(s)
            if "error" in r:
                return False, r["error"]
            challenge = b64d(r["challenge"])

            # 2) l'authenticator firma la challenge (response)
            sig, counter = self.authenticator.get_assertion(
                challenge, "segreteria.ateneo.it")

            # 3) invia PKv e la response sulla STESSA connessione: ottiene Cert(PKv)
            send_msg(s, {"type": "register", "student_id": self.student_id,
                         "assertion": b64e(sig), "counter": counter,
                         "pubkey_der": b64e(cu.pubkey_der(self.pk))})
            r = recv_msg(s)
            if "error" in r:
                return False, r["error"]
            self.cert_pem = b64d(r["cert_pem"])
            self.cert = pki.load_cert_pem(self.cert_pem)

            # 5) lo studente verifica Vrfy_PKCA(Cert(PKv)) e invia un ACK firmato
            ok = pki.verify_signed_by(self.cert, _load_ca(ca_cert_path))
            serial = self.cert.serial_number
            body = b"ack" + str(serial).encode() + (b"1" if ok else b"0")
            send_msg(s, {"type": "ack", "serial": serial, "ok": ok,
                         "sig": b64e(cu.pss_sign(self._sk, body))})
            recv_msg(s)                      # esito (completato / revocato)
        finally:
            s.close()
        if not ok:
            # 6) certificato corrotto: la SA lo revoca; lo studente rigenererebbe (PKv,SKv)
            return False, "certificato non valido (revoca richiesta)"
        return True, r["pseudonym"]

    def vote(self, bb_host, bb_port, ca_cert_path, pk_ce, ce_cert, ca_cert, v):
        """Prepara, cifra, firma e trasmette la scheda al BB, su un'unica
        sessione TLS (open_session -> cast)."""
        # 1) verifica che PK_CE sia autentica (firmata dalla SA)
        if not pki.verify_signed_by(ce_cert, ca_cert):
            return False, "PK_CE non autentica"

        s = tls_client_connect(bb_host, bb_port, ca_cert_path)
        try:
            # 2) apertura sessione: il BB risponde con il nonce Ns
            send_msg(s, {"type": "open_session", "cert_pem": b64e(self.cert_pem)})
            r = recv_msg(s)
            if "error" in r:
                return False, r["error"]
            Ns = b64d(r["Ns"])

            # 3) costruzione della scheda cifrata
            C = cu.oaep_encrypt(pk_ce, encode_vote(v, self.token))
            T = f"{time.time():.6f}"                    # timestamp
            sigma_v = cu.pss_sign(self._sk, C + self.token + Ns + T.encode())

            ballot = {
                "C": b64e(C), "token": b64e(self.token), "sigma_v": b64e(sigma_v),
                "cert_pem": b64e(self.cert_pem), "Ns": b64e(Ns), "T": T,
            }

            # 4) invio sulla STESSA connessione e ricezione della ricevuta sigma_BB
            send_msg(s, {"type": "cast", "ballot": ballot})
            r = recv_msg(s)
        finally:
            s.close()
        if "error" in r:
            return False, r["error"]
        ballot["sigma_bb"] = r["sigma_bb"]
        self._local_C = C                        # conservato (solo se ammessa) per la verifica
        self._receipt = ballot                   # record completo con sigma_BB
        return True, r["sigma_bb"]

    def verifica_individuale(self, bb_host, bb_port, ca_cert_path, ca_cert):
        """Controlla che la propria scheda sia inclusa e non alterata."""
        s = tls_client_connect(bb_host, bb_port, ca_cert_path)
        send_msg(s, {"type": "dump"})
        dump = recv_msg(s); s.close()
        M_B = b64d(dump["M_B"])
        bb_pub = pki.load_cert_pem(b64d(dump["bb_cert_pem"])).public_key()

        # 1) ritrova le schede col proprio token; sceglie quella con T massimo
        mine = [(i, b) for i, b in enumerate(dump["ballots"])
                if b64d(b["token"]) == self.token]
        if not mine:
            return False, "scheda non trovata"
        idx, b = max(mine, key=lambda ib: float(ib[1]["T"]))

        # 2) verifica sigma_v e sigma_BB
        C = b64d(b["C"]); Ns = b64d(b["Ns"]); T = b["T"]; sigma_v = b64d(b["sigma_v"])
        if not cu.pss_verify(self.pk, sigma_v, C + self.token + Ns + str(T).encode()):
            return False, "sigma_v non valida"
        if not cu.pss_verify(bb_pub, b64d(b["sigma_bb"]),
                             C + self.token + Ns + str(T).encode() + sigma_v
                             + b64d(b["cert_pem"])):
            return False, "sigma_BB non valida"

        # 3) il ciphertext sul BB coincide con quello conservato localmente
        if C != self._local_C:
            return False, "ciphertext diverso da quello inviato"

        # 4) prova di inclusione di Merkle
        leaves = [record_bytes(x) for x in dump["ballots"]]
        proof = merkle.inclusion_proof(leaves, idx)
        if not merkle.verify_proof(leaves[idx], proof, M_B):
            return False, "prova di inclusione fallita"
        return True, "scheda inclusa e integra"
