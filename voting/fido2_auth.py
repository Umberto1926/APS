"""
Autenticazione studente <-> Segreteria basata su FIDO2 .

Modelliamo il meccanismo essenziale di FIDO2: un authenticator custodisce
una chiave privata SK_FIDO che non lascia mai il dispositivo; presso la
Segreteria (Relying Party) e' registrata solo la chiave pubblica PK_FIDO.

Sia l'ENROLLMENT sia l'AUTENTICAZIONE sono challenge/response asimmetrici
svolti su canale TLS reale:

  enrollment:     attestazione = Sign_SK_FIDO( H(c_reg || origin || "enroll") )
  autenticazione: sigma_FIDO   = Sign_SK_FIDO( H(c    || origin || counter ) )

- origin lega la response al dominio della SA (anti-riuso su altri servizi);
- counter crescente rivela tentativi di clonazione dell'authenticator;
- l'attestazione di enrollment prova il possesso di SK_FIDO per la PK_FIDO
  che si sta registrando.

"""

import secrets
from .crypto_utils import gen_rsa, pss_sign, pss_verify


class Authenticator:
    """Dispositivo dell'utente. La chiave privata non lascia mai questa classe."""

    def __init__(self):
        self._sk = None         # SK_FIDO (privata, incapsulata)
        self.pk = None          # PK_FIDO (pubblica, registrata presso la SA)
        self.counter = 0

    def make_credential(self):
        """Enrollment: genera la coppia specifica per la RP e ne restituisce
        la sola parte pubblica."""
        self._sk = gen_rsa(2048)
        self.pk = self._sk.public_key()
        return self.pk

    def attest(self, challenge: bytes, origin: str):
        """Enrollment: firma la challenge di registrazione (proof-of-possession)."""
        message = challenge + origin.encode() + b"enroll"
        return pss_sign(self._sk, message)

    def get_assertion(self, challenge: bytes, origin: str):
        """Autenticazione: firma la challenge incrementando il counter."""
        self.counter += 1
        message = challenge + origin.encode() + self.counter.to_bytes(4, "big")
        sig = pss_sign(self._sk, message)
        return sig, self.counter


class FidoVerifier:
    """Lato Segreteria (Relying Party)."""

    def __init__(self, origin: str = "segreteria.ateneo.it"):
        self.origin = origin
        self._registry = {}        # student_id -> {"pk":..., "last_counter":int}
        self._challenges = {}      # student_id -> challenge di autenticazione
        self._enroll_chal = {}     # student_id -> challenge di enrollment

    #  ENROLLMENT (su TLS)
    def is_enrolled(self, student_id: str) -> bool:
        return student_id in self._registry

    def new_enroll_challenge(self, student_id: str) -> bytes:
        c = secrets.token_bytes(32)
        self._enroll_chal[student_id] = c
        return c

    def complete_enrollment(self, student_id, pk_fido, attestation: bytes) -> bool:
        """Verifica l'attestazione con la PK_FIDO presentata e, se valida,
        registra la credenziale per lo studente."""
        chal = self._enroll_chal.get(student_id)
        if chal is None:
            return False
        message = chal + self.origin.encode() + b"enroll"
        if not pss_verify(pk_fido, attestation, message):
            return False
        self._registry[student_id] = {"pk": pk_fido, "last_counter": 0}
        del self._enroll_chal[student_id]
        return True

    #  AUTENTICAZIONE (su TLS)
    def new_challenge(self, student_id: str) -> bytes:
        if student_id not in self._registry:
            raise ValueError("studente non registrato per FIDO2")
        c = secrets.token_bytes(32)
        self._challenges[student_id] = c
        return c

    def verify(self, student_id: str, signature: bytes, counter: int) -> bool:
        """Verifica firma, origin (implicito) e monotonia del counter."""
        rec = self._registry.get(student_id)
        chal = self._challenges.get(student_id)
        if rec is None or chal is None:
            return False
        if counter <= rec["last_counter"]:        # clonazione / replay
            return False
        message = chal + self.origin.encode() + counter.to_bytes(4, "big")
        if not pss_verify(rec["pk"], signature, message):
            return False
        rec["last_counter"] = counter
        del self._challenges[student_id]
        return True
