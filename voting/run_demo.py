"""
Orchestratore: esegue l'intero protocollo su TLS reale (modulo ssl).

Avvia i due server (Segreteria e Bulletin Board) su socket TLS locali e
riproduce in sequenza tutte le fasi descritte in WP2:
  Setup -> Registrazione -> Votazione -> Scrutinio -> Verifiche,
piu' un'ampia batteria di test di sicurezza che riproduce gli attacchi del
threat model e mostra come il sistema li respinge o li rende rilevabili.

Le fasi di registrazione e votazione sono eseguite IN PARALLELO sfruttando i server concorrenti: e' il comportamento di N studenti
reali che agiscono contemporaneamente.

Uso:        python -m voting.run_demo

"""

import os
import time
import tempfile
from concurrent.futures import ThreadPoolExecutor

from . import pki
from . import crypto_utils as cu
from . import merkle
from .segreteria import Segreteria
from .bulletin_board import BulletinBoard
from .commissione import CommissioneElettorale, rebuild_private_key
from .voter import Voter
from .ballot import encode_vote
from .ballot_record import record_bytes
from .observer import verifica_universale
from .netmsg import send_msg, recv_msg, tls_client_connect, b64e, b64d
from . import shamir

SA_HOST, SA_PORT = "localhost", 8443
BB_HOST, BB_PORT = "localhost", 9443
CANDIDATI = ["Lista A", "Lista B", "Lista C"]      # k = 3 candidati
K = len(CANDIDATI)

# Numero di aventi diritto "regolari": configurabile per i test di carico.
N_STUDENTI = int(os.environ.get("VOTO_N", "20"))
WORKERS = int(os.environ.get("VOTO_WORKERS", "32"))


#  utilita'
def bb_request(ca_path, obj):
    s = tls_client_connect(BB_HOST, BB_PORT, ca_path)
    send_msg(s, obj)
    r = recv_msg(s); s.close()
    return r


def bb_cast(ca_path, ballot):
    return bb_request(ca_path, {"type": "cast", "ballot": ballot})


def bb_open(ca_path, cert_pem):
    return bb_request(ca_path, {"type": "open_session", "cert_pem": b64e(cert_pem)})


def banner(txt):
    print("\n" + "=" * 64 + f"\n  {txt}\n" + "=" * 64)


def make_ballot(v, pk_ce, Ns, scelta=1, T=None,
                wrong_token=False, bad_sigma=False, tamper_C=False):
    """Costruisce un record di scheda (eventualmente malevolo) per i test."""
    token = os.urandom(32) if wrong_token else v.token
    C = cu.oaep_encrypt(pk_ce, encode_vote(scelta, v.token))
    if T is None:
        T = repr(time.time())
    sigma_v = cu.pss_sign(v._sk, C + token + Ns + T.encode())
    if tamper_C:
        ba = bytearray(C); ba[0] ^= 0x01; C = bytes(ba)   # firma non piu' valida
    if bad_sigma:
        sigma_v = os.urandom(256)
    return {"C": b64e(C), "token": b64e(token), "sigma_v": b64e(sigma_v),
            "cert_pem": b64e(v.cert_pem), "Ns": b64e(Ns), "T": T}


def main():
    pki_dir = tempfile.mkdtemp(prefix="voto_pki_")
    main_ids = [f"studente{i:03d}" for i in range(1, N_STUDENTI + 1)]
    # identita' aggiuntive usate solo dai test di sicurezza (aventi diritto)
    RVK, FIDO_V = "studente_revoca", "studente_fido"
    eligible = main_ids + [RVK, FIDO_V]

    #  FASE 0: SETUP 
    banner("FASE 0 - SETUP (SA Root CA, CE+Shamir, BB)")
    sa = Segreteria(eligible, pki_dir, SA_HOST, SA_PORT)
    sa.start()
    ca_path = sa.ca_cert_path
    print(f"SA Root CA in ascolto su {SA_HOST}:{SA_PORT}; PK_CA out-of-band: {ca_path}")

    ce = CommissioneElettorale(sa, k=K, t=3, n=5)
    print(f"CE: PK_CE generata, fattore primo (3,5)-Shamir tra {ce.n} commissari; "
          f"Cert(PK_CE) valido={pki.verify_signed_by(ce.cert, sa.ca_cert)}")

    bb = BulletinBoard(sa.ca_cert, pki_dir, sa, BB_HOST, BB_PORT)
    bb.start()
    print(f"BB in ascolto su {BB_HOST}:{BB_PORT}")
    time.sleep(0.3)

    #  FASE 1: REGISTRAZIONE 
    banner(f"FASE 1 - REGISTRAZIONE (FIDO2 + Cert(PKv) su TLS) - {N_STUDENTI} studenti")

    def make_and_register(sid):
        v = Voter(sid)
        v.enroll_fido(SA_HOST, SA_PORT, ca_path)        # enrollment FIDO2 su TLS
        ok, info = v.register(SA_HOST, SA_PORT, ca_path)
        return v, ok, info

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        reg = list(ex.map(make_and_register, main_ids))
    dt_reg = time.perf_counter() - t0
    voters = [r[0] for r in reg]
    print(f"  {sum(1 for _, ok, _ in reg if ok)}/{N_STUDENTI} studenti registrati  "
          f"[{dt_reg:.2f}s]")

    # voter dedicato al test di revoca (registrato regolarmente)
    rvk = Voter(RVK)
    rvk.enroll_fido(SA_HOST, SA_PORT, ca_path)
    rvk.register(SA_HOST, SA_PORT, ca_path)

    print(f"  Log certificati: {len(sa.cert_log()['certs'])} emessi, "
          f"N_aventi={sa.n_aventi}, M_C pubblicata")

    #  FASE 2: VOTAZIONE
    banner("FASE 2 - VOTAZIONE (scheda cifrata + firmata su TLS)")
    scelte = [((i % K) + 1) for i in range(N_STUDENTI)]   # preferenze cicliche

    def do_vote(pair):
        v, scelta = pair
        return (v, *v.vote(BB_HOST, BB_PORT, ca_path, ce.public_key, ce.cert,
                           sa.ca_cert, scelta))

    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        votes = list(ex.map(do_vote, zip(voters, scelte)))
    dt_vote = time.perf_counter() - t0
    n_ok = sum(1 for _, ok, _ in votes if ok)
    print(f"  {n_ok}/{N_STUDENTI} schede ammesse  [{dt_vote:.2f}s -> "
          f"{N_STUDENTI/max(dt_vote,1e-9):.0f} schede/s]")

    # Re-voting legittimo: i primi due studenti cambiano preferenza (conta T max)
    time.sleep(0.05)
    voters[0].vote(BB_HOST, BB_PORT, ca_path, ce.public_key, ce.cert, sa.ca_cert, 2)
    voters[1].vote(BB_HOST, BB_PORT, ca_path, ce.public_key, ce.cert, sa.ca_cert, 3)
    print("  Re-voting di 2 studenti (sostituzione): conta solo la scheda con T massimo")

    #  BATTERIA DI ATTACCHI 
    banner("TEST DI SICUREZZA - batteria di attacchi (threat model WP1)")
    results = []

    def rec(label, prop, rejected, detail):
        results.append(rejected)
        tag = "RESPINTO" if rejected else "NON RESPINTO(!)"
        print(f"  [{'OK' if rejected else 'KO'}] {label:<34} {prop:<16} {tag}: {detail}")

    # --- Autenticita' / Unicita' (enrollment e registrazione, lato SA) ---
    intruso = Voter("intruso999")
    ok, info = intruso.enroll_fido(SA_HOST, SA_PORT, ca_path)   # non avente diritto
    rec("Enrollment non avente diritto", "Autenticita'", not ok, info)

    ok, info = voters[0].register(SA_HOST, SA_PORT, ca_path)
    rec("Doppia registrazione", "Unicita'", not ok, info)

    # Enrollment FIDO2 con attestazione contraffatta (FIDO_V non ancora enrolled)
    junk = cu.gen_rsa(2048)
    s = tls_client_connect(SA_HOST, SA_PORT, ca_path)
    send_msg(s, {"type": "enroll_challenge", "student_id": FIDO_V}); recv_msg(s)
    send_msg(s, {"type": "enroll", "student_id": FIDO_V,
                 "pubkey_der": b64e(cu.pubkey_der(junk.public_key())),
                 "attestation": b64e(os.urandom(256))})
    r = recv_msg(s); s.close()
    rec("Attestazione enrollment falsa", "Autenticita'", "error" in r, r.get("error", "?"))

    # Enrollment legittimo, poi response di AUTENTICAZIONE contraffatta
    fv = Voter(FIDO_V); fv.enroll_fido(SA_HOST, SA_PORT, ca_path)
    s = tls_client_connect(SA_HOST, SA_PORT, ca_path)
    send_msg(s, {"type": "fido_challenge", "student_id": FIDO_V}); recv_msg(s)
    send_msg(s, {"type": "register", "student_id": FIDO_V,
                 "assertion": b64e(os.urandom(256)), "counter": 1,
                 "pubkey_der": b64e(cu.pubkey_der(fv.pk))})
    r = recv_msg(s); s.close()
    rec("FIDO2 response contraffatta", "Autenticita'", "error" in r, r.get("error", "?"))

    # Sostituzione di una chiave istituzionale in setup (MITM): la SA rifiuta
    # perché il commitment SHA-256 pubblicato non corrisponde alla chiave presentata.
    try:
        sa.sign_ce(cu.gen_rsa(2048).public_key())
        setup_ok = False
    except Exception:
        setup_ok = True
    rec("Chiave istituzionale sostituita (setup)", "Autenticita'", setup_ok,
        "commitment SHA-256 non corrispondente")

    # --- Autenticita' (votazione, lato BB) ---
    fake_key, fake_ca = pki.create_root_ca("CA Fraudolenta")
    victim = cu.gen_rsa(2048)
    fake_cert = pki.issue_voter_cert(fake_key, fake_ca, victim.public_key(), "fake")
    r = bb_open(ca_path, pki.cert_pem(fake_cert))
    rec("Cert da CA fraudolenta", "Autenticita'", "error" in r, r.get("error", "?"))

    # certificato revocato (CRL)
    sa.revoke(rvk.cert.serial_number)
    r = bb_open(ca_path, rvk.cert_pem)
    rec("Certificato revocato (CRL)", "Autenticita'", "error" in r, r.get("error", "?"))

    # --- Integrita' / freschezza (votazione) ---
    # replay: re-invio di una scheda gia' ammessa (nonce consumato)
    replay = dict(voters[2]._receipt); replay.pop("sigma_bb", None)
    r = bb_cast(ca_path, replay)
    rec("Replay (nonce consumato)", "Integrita'", "error" in r, r.get("error", "?"))

    a = voters[3]
    Ns = b64d(bb_open(ca_path, a.cert_pem)["Ns"])
    r = bb_cast(ca_path, make_ballot(a, ce.public_key, Ns, tamper_C=True))
    rec("MITM: C alterato (sigma_v ko)", "Integrita'", "error" in r, r.get("error", "?"))

    Ns = b64d(bb_open(ca_path, a.cert_pem)["Ns"])
    r = bb_cast(ca_path, make_ballot(a, ce.public_key, Ns, bad_sigma=True))
    rec("Firma elettore contraffatta", "Integrita'", "error" in r, r.get("error", "?"))

    Ns = b64d(bb_open(ca_path, a.cert_pem)["Ns"])
    r = bb_cast(ca_path, make_ballot(a, ce.public_key, Ns, wrong_token=True))
    rec("Token incoerente con PKv", "Pseudonimato", "error" in r, r.get("error", "?"))

    # nonce mai emesso dal BB
    r = bb_cast(ca_path, make_ballot(a, ce.public_key, os.urandom(32)))
    rec("Nonce non emesso", "Freschezza", "error" in r, r.get("error", "?"))

    # nonce legato a un altro elettore (binding token<->nonce)
    Ns_b = b64d(bb_open(ca_path, voters[4].cert_pem)["Ns"])   # nonce di voters[4]
    r = bb_cast(ca_path, make_ballot(a, ce.public_key, Ns_b))  # usato da 'a'
    rec("Nonce di un altro elettore", "Freschezza", "error" in r, r.get("error", "?"))

    # timestamp fuori finestra
    Ns = b64d(bb_open(ca_path, a.cert_pem)["Ns"])
    old_T = repr(time.time() - 100000)
    r = bb_cast(ca_path, make_ballot(a, ce.public_key, Ns, T=old_T))
    rec("Timestamp fuori finestra", "Freschezza", "error" in r, r.get("error", "?"))

    # oltre il limite di re-voting (3a scheda per lo stesso token)
    r = voters[0].vote(BB_HOST, BB_PORT, ca_path, ce.public_key, ce.cert, sa.ca_cert, 1)
    rec("Oltre limite re-voting", "Unicita'", not r[0], r[1])

    #  FASE 3: SCRUTINIO 
    banner("FASE 3 - SCRUTINIO (ricostruzione Shamir + decifratura)")
    close = bb_request(ca_path, {"type": "close"})
    print(f"  Urne chiuse. M_B pubblicata: {close['M_B'][:24]}...")
    dump = ce.download_ballots(BB_HOST, BB_PORT, ca_path)   # CE -> BB su TLS reale

    # voto dopo la chiusura delle urne
    Ns2 = bb_open(ca_path, a.cert_pem)
    after = ("error" in Ns2) or ("error" in bb_cast(ca_path,
              {"C": b64e(b"x"), "token": b64e(a.token), "sigma_v": b64e(b"x"),
               "cert_pem": b64e(a.cert_pem), "Ns": b64e(os.urandom(32)),
               "T": repr(time.time())}))
    rec("Voto dopo chiusura urne", "Integrita'", after, "urne chiuse")

    # Integrita' del registro: alterazione di 1 byte
    M_B = b64d(dump["M_B"])
    leaves = [record_bytes(b) for b in dump["ballots"]]
    tampered_leaves = list(leaves)
    bad = bytearray(tampered_leaves[0]); bad[10] ^= 0x01
    tampered_leaves[0] = bytes(bad)
    new_root = merkle.merkle_root(tampered_leaves)
    proof = merkle.inclusion_proof(leaves, 0)
    incl_fails = not merkle.verify_proof(tampered_leaves[0], proof, M_B)
    rec("Alterazione registro (1 byte)", "Integrita'",
        new_root != M_B and incl_fails, "radice M_B incoerente")

    # Soglia Shamir: meno di t=3 quote non ricostruiscono la chiave
    known_C = b64d(voters[5]._receipt["C"])
    try:
        wrong_p = shamir.reconstruct([c.share for c in ce.commissari[:2]])  # 2 quote
        bad_key = rebuild_private_key(wrong_p, ce.N, ce.e)
        cu.oaep_decrypt(bad_key, known_C)
        thr_ok = False
    except Exception:
        thr_ok = True
    rec("Soglia Shamir (2<t quote)", "Segretezza", thr_ok, "chiave non ricostruibile")

    result = ce.scrutinio(dump, sa.ca_cert)
    print(f"\n  Schede: {result['stats']}")
    print(f"  Firme individuali dei commissari: {len(result['signatures'])} (soglia t=3)")
    for j, name in enumerate(CANDIDATI, start=1):
        print(f"    {name}: {result['counts'][str(j)]} voti")


    #  TEST DI SICUREZZA 
    banner("TEST DI SICUREZZA - Attacchi mirati alla Verifica Universale")
    
    # Risultato manomesso -> verifica universale deve fallire
    tampered_result = dict(result); tampered_result["counts"] = dict(result["counts"])
    tampered_result["counts"]["1"] += 5
    rep_bad = verifica_universale(dump, tampered_result, sa.cert_log(),
                                  sa.ca_cert, sa.is_revoked, K)
    rec("Risultato manomesso Aggiunti 5 voti", "Verificabilita'", not rep_bad["ESITO"],
        f"riconteggio_coerente={rep_bad['riconteggio_coerente']}")

    
    # 2. Attacco: Manomissione del registro BB (Incoerenza Merkle)
    # Alteriamo i dati grezzi estratti dal BB prima di passarli alla verifica
    tampered_dump = dict(dump)
    # Prendiamo la prima scheda e alteriamo il token (corruzione dati)
    bad_ballots = list(dump["ballots"])
    corrupted_ballot = dict(bad_ballots[0])
    corrupted_ballot["token"] = b64e(os.urandom(32))
    bad_ballots[0] = corrupted_ballot
    tampered_dump["ballots"] = bad_ballots
    
    # Nota: M_B rimane quella originale, quindi la verifica della radice fallirà
    rep_bad_merkle = verifica_universale(tampered_dump, result, sa.cert_log(),
                                         sa.ca_cert, sa.is_revoked, K)
    rec("Registro BB manomesso", "Integrità", not rep_bad_merkle["ESITO"], 
        "la radice di Merkle non coincide con le schede presenti")

    #  FASE 4: VERIFICA UNIVERSALE 
    banner("FASE 4 - VERIFICA UNIVERSALE (osservatore, solo chiavi pubbliche)")
    report = verifica_universale(dump, result, sa.cert_log(),
                                 sa.ca_cert, sa.is_revoked, K)
    for kk, vv in report.items():
        if kk != "ESITO":
            print(f"    [{'OK' if vv else 'KO'}] {kk}")
    print(f"  ESITO COMPLESSIVO: {'VALIDA' if report['ESITO'] else 'NON VALIDA'}")

    # FASE 5: VERIFICA INDIVIDUALE 
    banner("FASE 5 - VERIFICA INDIVIDUALE (elettore)")
    for idx in (0, 7, 13):
        ok, info = voters[idx].verifica_individuale(BB_HOST, BB_PORT, ca_path, sa.ca_cert)
        print(f"  {voters[idx].student_id}: {info} ({'OK' if ok else 'KO'})")

    bb.stop(); sa.stop()
    print("\nSimulazione completata.\n")


if __name__ == "__main__":
    main()