"""

Segreteria d'Ateneo (SA): Root CA + server di registrazione su TLS reale.

  - Root CA: emette e firma tutti i certificati X.509 del sistema;
  - autentica gli studenti via FIDO2 e rilascia il certificato pseudonimo
    Cert(PKv);
  - mantiene il log pubblico append-only dei certificati (radice M_C) e
    la CRL firmata;
  - pubblica N_aventi (numero ufficiale degli aventi diritto).

Il server di registrazione accetta connessioni TLS reali (modulo ssl) sul
proprio endpoint; il certificato del server e' firmato dalla Root CA.
"""

import os
import ssl
import socket
import secrets
import threading

from cryptography.hazmat.primitives.serialization import Encoding, load_der_public_key

from . import pki
from . import crypto_utils as cu
from . import merkle
from .fido2_auth import FidoVerifier
from .netmsg import send_msg, recv_msg, b64e, b64d


class Segreteria:
    def __init__(self, eligible_students, pki_dir, host="localhost", port=8443):
        self.host, self.port = host, port
        self.pki_dir = pki_dir
        os.makedirs(pki_dir, exist_ok=True)

        #  Root CA (PK_CA, SK_CA) e trust anchor 
        self.ca_key, self.ca_cert = pki.create_root_ca()
        self.n_aventi = len(eligible_students)          # N_aventi pubblicato
        self._eligible = set(eligible_students)         # registro aventi diritto
        self._registered = set()                        # log interno registrazioni

        # FIDO2 
        self.fido = FidoVerifier()

        #  Log pubblico dei certificati (Merkle M_C)
        self._cert_log = []        # lista di DER dei certificati emessi agli elettori

        #  CRL firmata 
        self._revoked = set()      # serial number revocati

        #  Certificato TLS del server di registrazione 
        srv_key = cu.gen_rsa(2048)
        srv_cert = pki.issue_server_cert(self.ca_key, self.ca_cert,
                                         srv_key.public_key(), "Segreteria - endpoint")
        self._srv_key_path = os.path.join(pki_dir, "sa_server_key.pem")
        self._srv_cert_path = os.path.join(pki_dir, "sa_server_cert.pem")
        with open(self._srv_key_path, "wb") as f:
            f.write(cu.privkey_pem(srv_key))
        with open(self._srv_cert_path, "wb") as f:
            f.write(pki.cert_pem(srv_cert))

        self.ca_cert_path = os.path.join(pki_dir, "root_ca.pem")
        with open(self.ca_cert_path, "wb") as f:
            f.write(pki.cert_pem(self.ca_cert))

        self._server_sock = None
        self._thread = None
        self._running = False
        self._lock = threading.Lock()   # protegge log certificati e registrazioni
        self._pending = {}              # serial -> PKv in attesa di ACK (§2.6)
        self._inst_commitments = {}     # entita' -> commitment SHA-256(PK) (setup)

    # FIDO2: l'enrollment avviene ora su TLS (handler _dispatch), non piu' in-processo
    # Emissione certificati di infrastruttura (chiamate locali nel setup)
    def publish_commitment(self, entity, commitment):
        """Registro istituzionale: CE/BB pre-pubblicano c=SHA-256(PK) prima di
        trasmettere la chiave, così la SA può rilevare una sostituzione MITM."""
        self._inst_commitments[entity] = commitment

    def _check_commitment(self, entity, pub):
        c = self._inst_commitments.get(entity)
        if c is None or cu.sha256(cu.pubkey_der(pub)) != c:
            raise ValueError(
                f"commitment SHA-256 non corrispondente per {entity}: "
                f"certificazione rifiutata")

    def sign_ce(self, ce_pub):
        self._check_commitment("CE", ce_pub)          # anti-MITM sulla chiave CE
        return pki.issue_ce_cert(self.ca_key, self.ca_cert, ce_pub)

    def sign_commissioner(self, pub, idx):
        return pki.issue_commissioner_cert(self.ca_key, self.ca_cert, pub, idx)

    def sign_bb(self, bb_pub):
        self._check_commitment("BB", bb_pub)          # anti-MITM sulla chiave BB
        return pki.issue_bb_cert(self.ca_key, self.ca_cert, bb_pub)

    # CRL firmata 
    def revoke(self, serial: int):
        self._revoked.add(serial)

    def is_revoked(self, serial: int) -> bool:
        return serial in self._revoked

    def get_crl(self):
        """Ritorna la CRL firmata con SK_CA (lista serial + firma PSS)."""
        body = ",".join(str(s) for s in sorted(self._revoked)).encode()
        sig = cu.pss_sign(self.ca_key, body)
        return {"revoked": sorted(self._revoked), "sig": b64e(sig)}

    # Log pubblico dei certificati (radice M_C)
    def cert_log(self):
        return {
            "certs": [b64e(d) for d in self._cert_log],
            "root": b64e(merkle.merkle_root(self._cert_log)),
            "n_aventi": self.n_aventi,
        }

    # Server TLS di registrazione
    def start(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self._srv_cert_path, self._srv_key_path)
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
            # Una connessione per thread: gestione concorrente dei client.
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        # Keep-alive: una sola connessione TLS porta l'intera sessione di
        # registrazione (challenge -> register). Si itera finche' il client
        # non chiude.
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

        if t == "enroll_challenge":
            # Enrollment FIDO2 (su TLS): challenge di registrazione.
            sid = req["student_id"]
            with self._lock:
                if sid not in self._eligible:
                    send_msg(conn, {"error": "non avente diritto"}); return
                if self.fido.is_enrolled(sid):
                    send_msg(conn, {"error": "authenticator gia' registrato"}); return
                c = self.fido.new_enroll_challenge(sid)
            send_msg(conn, {"challenge": b64e(c)})

        elif t == "enroll":
            # Enrollment FIDO2 (su TLS): registra PK_FIDO se l'attestazione e' valida.
            sid = req["student_id"]
            with self._lock:
                if sid not in self._eligible:
                    send_msg(conn, {"error": "non avente diritto"}); return
                if self.fido.is_enrolled(sid):
                    send_msg(conn, {"error": "authenticator gia' registrato"}); return
                pk_fido = self._load_pub(b64d(req["pubkey_der"]))
                ok = self.fido.complete_enrollment(sid, pk_fido,
                                                   b64d(req["attestation"]))
            if ok:
                send_msg(conn, {"status": "enrolled"})
            else:
                send_msg(conn, {"error": "attestazione FIDO2 non valida"})

        elif t == "fido_challenge":
            sid = req["student_id"]
            try:
                c = self.fido.new_challenge(sid)
                send_msg(conn, {"challenge": b64e(c)})
            except ValueError:
                send_msg(conn, {"error": "studente sconosciuto"})

        elif t == "register":
            sid = req["student_id"]
            with self._lock:
                # 1) studente avente diritto e non gia' registrato
                if sid not in self._eligible:
                    send_msg(conn, {"error": "non avente diritto"})
                    return
                if sid in self._registered:
                    send_msg(conn, {"error": "studente gia' registrato"})
                    return
                # 2) verifica della response FIDO2
                ok = self.fido.verify(sid, b64d(req["assertion"]), req["counter"])
                if not ok:
                    send_msg(conn, {"error": "autenticazione FIDO2 fallita"})
                    return
                # 3) firma del certificato pseudonimo sulla PKv ricevuta
                voter_pub = self._load_pub(b64d(req["pubkey_der"]))
                pseudonym = "voter-" + secrets.token_hex(6)
                cert = pki.issue_voter_cert(self.ca_key, self.ca_cert,
                                            voter_pub, pseudonym)
                # 4) inserimento nel log pubblico (aggiorna M_C)
                self._cert_log.append(cert.public_bytes(Encoding.DER))
                self._registered.add(sid)
                self._pending[cert.serial_number] = voter_pub   # attende ACK
            send_msg(conn, {"cert_pem": b64e(pki.cert_pem(cert)),
                            "pseudonym": pseudonym,
                            "serial": cert.serial_number})

        elif t == "ack":
            # passi 5-6: lo studente conferma (o segnala) il certificato.
            serial = req["serial"]; ok = bool(req["ok"]); sig = b64d(req["sig"])
            with self._lock:
                pub = self._pending.pop(serial, None)
            if pub is None:
                send_msg(conn, {"error": "ack sconosciuto"}); return
            body = b"ack" + str(serial).encode() + (b"1" if ok else b"0")
            if not cu.pss_verify(pub, sig, body):
                send_msg(conn, {"error": "ack non valido"}); return
            if not ok:
                self.revoke(serial)          # cert corrotto in transito: revoca
                send_msg(conn, {"status": "revocato"})
            else:
                send_msg(conn, {"status": "completato"})

        elif t == "get_crl":
            send_msg(conn, self.get_crl())

        else:
            send_msg(conn, {"error": "richiesta sconosciuta"})

    @staticmethod
    def _load_pub(der: bytes):
        return load_der_public_key(der)
