"""
Bulletin Board (BB): registro pubblico attivo su TLS reale.

  - apre la sessione di voto generando un nonce monouso Ns legato al token;
  - riceve la scheda, esegue TUTTE le verifiche crittografiche, firma
    l'ammissione con SK_BB (sigma_BB) e la archivia in modo append-only;
  - a urne chiuse pubblica la radice di Merkle M_B (impegno sulle schede).

La compromissione di SK_BB non rivela alcun voto (i voti sono cifrati con
PK_CE) e qualsiasi scheda forgiata sarebbe priva di una sigma_v valida.
"""

import os
import ssl
import time
import socket
import secrets
import threading

from cryptography.hazmat.primitives.serialization import load_der_public_key
from .netmsg import send_msg, recv_msg, tls_client_connect, b64e, b64d
from . import pki
from . import crypto_utils as cu
from . import merkle
from .ballot_record import record_bytes

REVOTE_LIMIT = 2          # max 2 schede per token
TIME_WINDOW = 3600        # finestra di freschezza del timestamp (secondi)


class BulletinBoard:
    def __init__(self, ca_cert, pki_dir, sa,
                 host="localhost", port=9443):
        self.host, self.port = host, port
        self.ca_cert = ca_cert               # trust anchor (PK_CA)
        self._sa_host, self._sa_port = sa.host, sa.port
        self._ca_cert_path = sa.ca_cert_path
        self._revoked_serials = set()
        # Identita' del BB: Cert(PK_BB) firmato dalla SA, usato per sigma_BB e per TLS.
        self.bb_key = cu.gen_rsa(2048)
        sa.publish_commitment("BB", cu.sha256(cu.pubkey_der(self.bb_key.public_key())))
        self.bb_cert = sa.sign_bb(self.bb_key.public_key())
        self._key_path = os.path.join(pki_dir, "bb_key.pem")
        self._cert_path = os.path.join(pki_dir, "bb_cert.pem")
        with open(self._key_path, "wb") as f:
            f.write(cu.privkey_pem(self.bb_key))
        with open(self._cert_path, "wb") as f:
            f.write(pki.cert_pem(self.bb_cert))

        # Stato del registro
        self.ballots = []                    # lista di record (dict di transport)
        self._nonces = {}                    # Ns  -> {"token":.., "used":bool}
        self._revote = {}                    # token -> contatore
        self._pairs = set()                  # (token, C ) gia' visti
        self.closed = False
        self.M_B = None

        self._lock = threading.Lock()
        self._server_sock = None
        self._thread = None
        self._running = False


    # Server TLS
    def start(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._cert_path, self._key_path)
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw.bind((self.host, self.port))
        raw.listen(16)
        self._server_sock = ctx.wrap_socket(raw, server_side=True)
        self._server_sock.settimeout(1.0)
        self._running = True
        self._thread = threading.Thread(target=self._serve_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
        if self._server_sock:
            self._server_sock.close()

    def _serve_loop(self):
        while self._running:
            try:
                conn, _ = self._server_sock.accept()
            except (socket.timeout, ssl.SSLError):
                continue
            except OSError:
                break
            # Una connessione per thread: gestione concorrente dei votanti.
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()


    # Gestione richieste
    def _handle(self, conn):
        # Keep-alive: la stessa connessione TLS porta l'intera sessione di
        # voto (open_session -> cast). Si itera finche' il client non chiude.
        try:
            while True:
                try:
                    req = recv_msg(conn)
                except (ConnectionError, OSError, ssl.SSLError):
                    break
                self._dispatch(conn, req)
        finally:
            conn.close()

    def _dispatch(self, conn, req):
        t = req.get("type")
        if t == "open_session":
            send_msg(conn, self._open_session(req))
        elif t == "cast":
            send_msg(conn, self._cast(req["ballot"]))
        elif t == "close":
            send_msg(conn, self._close())
        elif t == "dump":
            with self._lock:
                send_msg(conn, {"ballots": list(self.ballots),
                                "M_B": b64e(self.M_B) if self.M_B else None,
                                "bb_cert_pem": b64e(pki.cert_pem(self.bb_cert))})
        else:
            send_msg(conn, {"error": "richiesta sconosciuta"})

    def _verify_cert(self, cert):
        """Cert firmato dalla SA e non revocato (CRL)."""
        if not pki.verify_signed_by(cert, self.ca_cert):
            return False
        if self.is_revoked(cert.serial_number):
            return False
        if not pki.is_cert_valid_now(cert):
            return False
        return True

    def _open_session(self, req):
        self.refresh_crl()
        cert = pki.load_cert_pem(b64d(req["cert_pem"]))
        if not self._verify_cert(cert):
            return {"error": "certificato non valido o revocato"}
        token = cu.sha256(cu.pubkey_der(cert.public_key()))
        Ns = secrets.token_bytes(32)         # nonce monouso a 256 bit
        with self._lock:
            self._nonces[Ns.hex()] = {"token": token.hex(), "used": False}
        return {"Ns": b64e(Ns), "timeout": TIME_WINDOW}

    def _cast(self, b):
        self.refresh_crl()
        with self._lock:
            if self.closed:
                return {"error": "urne chiuse"}

            cert = pki.load_cert_pem(b64d(b["cert_pem"]))
            C = b64d(b["C"]); token = b64d(b["token"])
            Ns = b64d(b["Ns"]); sigma_v = b64d(b["sigma_v"]); T = b["T"]

            # (1) certificato valido e non revocato
            if not self._verify_cert(cert):
                return {"error": "certificato non valido o revocato (CRL)"}
            # (2) token coerente con PKv
            pub = cert.public_key()
            if token != cu.sha256(cu.pubkey_der(pub)):
                return {"error": "token incoerente con PKv"}
            # (3) firma dell'elettore valida su (C || token || Ns || T)
            msg = C + token + Ns + str(T).encode()
            if not cu.pss_verify(pub, sigma_v, msg):
                return {"error": "firma dell'elettore non valida"}
            # (4) nonce presente, legato al token e non consumato
            ns_rec = self._nonces.get(Ns.hex())
            if ns_rec is None or ns_rec["used"] or ns_rec["token"] != token.hex():
                return {"error": "nonce non valido o consumato"}
            # (5) timestamp nella finestra valida
            if abs(time.time() - float(T)) > TIME_WINDOW:
                return {"error": "timestamp fuori finestra"}
            # (6) limite di re-voting per token
            if self._revote.get(token.hex(), 0) >= REVOTE_LIMIT:
                return {"error": "limite re-voting raggiunto"}
            # (7) anti copia-revoting: niente stessa coppia (token, C)
            if (token.hex(), C.hex()) in self._pairs:
                return {"error": "scheda duplicata (stessa coppia token,C)"}

            # Tutte le verifiche superate: firma di ammissione sigma_BB
            sigma_bb_msg = C + token + Ns + str(T).encode() + sigma_v + b64d(b["cert_pem"])
            sigma_bb = cu.pss_sign(self.bb_key, sigma_bb_msg)

            record = {
                "C": b["C"], "token": b["token"], "sigma_v": b["sigma_v"],
                "cert_pem": b["cert_pem"], "Ns": b["Ns"], "T": T,
                "sigma_bb": b64e(sigma_bb),
            }
            self.ballots.append(record)
            ns_rec["used"] = True
            self._revote[token.hex()] = self._revote.get(token.hex(), 0) + 1
            self._pairs.add((token.hex(), C.hex()))
            return {"ack": True, "sigma_bb": b64e(sigma_bb)}

    def _close(self):
        with self._lock:
            self.closed = True
            leaves = [record_bytes(b) for b in self.ballots]
            self.M_B = merkle.merkle_root(leaves)
            return {"M_B": b64e(self.M_B)}
    
    def refresh_crl(self):
        """Scarica la CRL firmata dalla SA su TLS e ne verifica la firma
        con PK_CA prima di fidarsene (§2.2.9)."""
        s = tls_client_connect(self._sa_host, self._sa_port, self._ca_cert_path)
        try:
            send_msg(s, {"type": "get_crl"})
            crl = recv_msg(s)
        finally:
            s.close()
        # Si ricostruisce ESATTAMENTE la stringa che la SA ha firmato in
        # get_crl(): ",".join(serial ordinati). Se non combacia, la firma
        # non verifica.
        body = ",".join(str(x) for x in sorted(crl["revoked"])).encode()
        if not cu.pss_verify(self.ca_cert.public_key(), b64d(crl["sig"]), body):
            raise ValueError("CRL con firma non valida")
        self._revoked_serials = set(crl["revoked"])

    def is_revoked(self, serial):
        return serial in self._revoked_serials
