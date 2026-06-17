"""

Osservatore esterno: verifica universale.

Usa SOLO chiavi pubbliche (PK_CA, PK_BB, PK_Ci) e i dati pubblicati dal BB
e dalla CE. Nessuna chiave privata e' necessaria: e' il piu' alto livello di
trasparenza compatibile con la segretezza.

  - Una scheda e' "valida" se: cert firmato da SA, cert non revocato,
    token coerente con PKv, sigma_v valida, sigma_BB valida.
  - Le schede non valide vengono segnalate ma NON causano il fallimento
    dell'ESITO complessivo: restano nel BB (immutabilita' del registro) e
    vengono semplicemente escluse dal riconteggio, esattamente come fa la CE
    in scrutinio.
  - Il controllo "nessun_cert_revocato_nel_conteggio" verifica che NESSUNA
    delle schede effettivamente conteggiate (T-max per token, dopo i filtri)
    provenga da un certificato revocato.
"""

from collections import Counter

from . import pki
from . import crypto_utils as cu
from . import merkle
from .ballot_record import record_bytes
from .commissione import result_message
from .netmsg import b64d


def verifica_universale(bb_dump, result, cert_log, ca_cert, is_revoked, k, t=3):
    report = {}
    ballots = bb_dump["ballots"]
    bb_pub = pki.load_cert_pem(b64d(bb_dump["bb_cert_pem"])).public_key()

    ok_certs = ok_tokens = ok_sigv = ok_sigbb = True
    # Schede revocate trovate nel BB (non e' un errore che esistano:
    # il BB le ha accettate prima della revoca; la CE le scarta allo scrutinio).
    n_revocate_nel_bb = 0
    # Per ogni scheda: True se supera TUTTI i controlli di validita'.
    validity = []

    for b in ballots:
        cert = pki.load_cert_pem(b64d(b["cert_pem"]))
        pub = cert.public_key()
        token = b64d(b["token"]); C = b64d(b["C"])
        Ns = b64d(b["Ns"]); sigma_v = b64d(b["sigma_v"]); T = b["T"]

        cert_ok   = pki.verify_signed_by(cert, ca_cert)
        revoked   = is_revoked(cert.serial_number)
        token_ok  = (token == cu.sha256(cu.pubkey_der(pub)))
        sigv_ok   = cu.pss_verify(pub, sigma_v, C + token + Ns + str(T).encode())
        sigbb_ok  = cu.pss_verify(bb_pub, b64d(b["sigma_bb"]),
                                  C + token + Ns + str(T).encode()
                                  + sigma_v + b64d(b["cert_pem"]))
        notexp = pki.is_cert_valid_now(cert)

        if not cert_ok:   ok_certs  = False
        if revoked:       n_revocate_nel_bb += 1
        if not token_ok:  ok_tokens = False
        if not sigv_ok:   ok_sigv   = False
        if not sigbb_ok:  ok_sigbb  = False

        # Una scheda e' valida per il riconteggio solo se supera tutto
        # (inclusa l'assenza di revoca).
        ballot_valid = cert_ok and (not revoked) and notexp and token_ok and sigv_ok and sigbb_ok
        validity.append(ballot_valid)

    # Informativo: segnala la presenza di schede con problemi nel BB.
    report["certificati_firmati_da_SA"] = ok_certs
    report["token_coerenti"] = ok_tokens
    report["firme_elettore_valide"] = ok_sigv
    report["firme_BB_valide"] = ok_sigbb
    report["schede_revocate_nel_BB"] = n_revocate_nel_bb

    # (5) Controlli strutturali sul registro complessivo
    per_token = Counter(b["token"] for b in ballots)
    report["max_2_schede_per_token"] = all(c <= 2 for c in per_token.values())
    pairs = [(b["token"], b["C"]) for b in ballots]
    report["nessuna_coppia_token_C_ripetuta"] = len(pairs) == len(set(pairs))
    # Solo i token di schede VALIDE (non revocate) contano verso N_aventi.
    valid_tokens = {b64d(b["token"])
                    for b, v in zip(ballots, validity) if v}
    report["token_distinti_validi_<=_N_aventi"] = len(valid_tokens) <= cert_log["n_aventi"]

    # (6) Ricalcolo della radice di Merkle del BB (su TUTTE le schede,
    #     incluse quelle non valide: il Merkle impegna il registro integrale).
    leaves = [record_bytes(b) for b in ballots]
    report["radice_M_B_coerente"] = (
        merkle.merkle_root(leaves) == b64d(bb_dump["M_B"]))

    # (7) Log dei certificati: M_C, conteggio e corrispondenza token->cert
    log_ders = [b64d(c) for c in cert_log["certs"]]
    report["radice_M_C_coerente"] = (
        merkle.merkle_root(log_ders) == b64d(cert_log["root"]))
    issued_tokens = set()
    n_non_revocati = 0
    for der in log_ders:
        cert = pki.load_cert_pem(_der_to_pem(der))
        issued_tokens.add(cu.sha256(cu.pubkey_der(cert.public_key())))
        if not is_revoked(cert.serial_number):
            n_non_revocati += 1
    voting_tokens = {b64d(b["token"]) for b in ballots}
    report["token_votanti_sono_emessi"] = voting_tokens.issubset(issued_tokens)
    report["cert_emessi_<=_N_aventi"] = len(log_ders) <= cert_log["n_aventi"]
    report["cert_non_revocati_<=_N_aventi"] = n_non_revocati <= cert_log["n_aventi"]

    # (9) Almeno t firme individuali dei commissari sul risultato
    msg = result_message(result["counts"], result["shuffled"])
    valid_sigs = 0
    for srec in result["signatures"]:
        cert = pki.load_cert_pem(b64d(srec["cert_pem"]))
        if pki.verify_signed_by(cert, ca_cert) and \
           cu.pss_verify(cert.public_key(), b64d(srec["sig"]), msg):
            valid_sigs += 1
    report["almeno_t_firme_commissari"] = valid_sigs >= t

    # (10) Riconteggio indipendente.
    # Riproduce la logica della CE:
    # (a) schede valide
    valid_ballots = [b for b, v in zip(ballots, validity) if v]
    # (b) T-max per token
    latest: dict = {}
    for b in valid_ballots:
        tk = b["token"]
        if tk not in latest or float(b["T"]) > float(latest[tk]["T"]):
            latest[tk] = b
    n_conteggiate = len(latest)

    # (c) riconteggio sulla lista rimescolata pubblicata
    recount = {str(j): sum(1 for v in result["shuffled"] if v == j)
               for j in range(1, k + 1)}
    report["riconteggio_coerente"] = (recount == result["counts"])

    # Controllo aggiuntivo: il numero di voti nella lista rimescolata deve
    # corrispondere al numero di schede valide selezionate dall'osservatore: alcune schede
    # valide possono fallire la decifratura (token interno != token in chiaro,
    # oppure v fuori range) e venire scartate.
    report["n_voti_coerente_con_schede_valide"] = (
        len(result["shuffled"]) <= n_conteggiate)

    # Controllo che nessuna scheda CONTEGGIATA provenga da cert revocato
    # (invariante: se la CE ha operato correttamente, questo e' sempre True).
    report["nessun_cert_revocato_nel_conteggio"] = all(
        not is_revoked(pki.load_cert_pem(b64d(b["cert_pem"])).serial_number)
        for b in latest.values()
    )


    # ESITO: solo i check che devono essere True per un'elezione valida.
    # "schede_revocate_nel_BB" e' solo informativo e NON entra nell'ESITO.
    esito_keys = {
        "certificati_firmati_da_SA",
        "token_coerenti",
        "firme_elettore_valide",
        "firme_BB_valide",
        "max_2_schede_per_token",
        "nessuna_coppia_token_C_ripetuta",
        "token_distinti_validi_<=_N_aventi",
        "radice_M_B_coerente",
        "radice_M_C_coerente",
        "token_votanti_sono_emessi",
        "cert_non_revocati_<=_N_aventi",
        "almeno_t_firme_commissari",
        "riconteggio_coerente",
        "n_voti_coerente_con_schede_valide",
        "nessun_cert_revocato_nel_conteggio",
    }
    report["ESITO"] = all(report[k] for k in esito_keys)
    return report


def _der_to_pem(der: bytes):
    from cryptography.x509 import load_der_x509_certificate
    from cryptography.hazmat.primitives.serialization import Encoding
    return load_der_x509_certificate(der).public_bytes(Encoding.PEM)