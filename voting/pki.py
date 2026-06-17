"""
Infrastruttura a chiave pubblica a UN livello.

La Segreteria d'Ateneo assume il ruolo di Root CA: emette e firma
direttamente tutti i certificati end-entity (elettori pseudonimi, CE,
commissari, Bulletin Board, endpoint TLS dei server). Non c'e' CA
intermedia: meno chiavi attive = meno bersagli da proteggere.

I certificati X.509 sono firmati con RSA PKCS#1 v1.5 + SHA-256, lo schema
di default del formato X.509.
"""

import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization

from .crypto_utils import gen_rsa

_UTC = datetime.timezone.utc


def _name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Universita - Voto Elettronico"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


# Root CA 
def create_root_ca(common_name: str = "Segreteria Ateneo Root CA"):
    """Genera (PK_CA, SK_CA) e il certificato auto-firmato (subject == issuer).
    La parte pubblica PK_CA e' il trust anchor distribuito out-of-band."""
    key = gen_rsa(2048)
    subject = _name(common_name)
    now = datetime.datetime.now(_UTC)
    
    # Calcoliamo l'identificatore della chiave pubblica per SKI e AKI
    pub_key = key.public_key()
    ski = x509.SubjectKeyIdentifier.from_public_key(pub_key)
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)                       # self-signed
        .public_key(pub_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        # --- ESTENSIONI REALI PER LA ROOT CA ---
        .add_extension(ski, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pub_key), critical=False)
        # --------------------------------------
        .sign(key, hashes.SHA256())                 # PKCS#1 v1.5 + SHA-256
    )
    return key, cert


def _issue(ca_key, ca_cert, subject_pub, common_name, days=None, hours=None,
           server_san=None, eku=None):
    """Emette un certificato end-entity (ca=False) firmato dalla Root CA."""
    now = datetime.datetime.now(_UTC)
    delta = datetime.timedelta(days=days) if days else datetime.timedelta(hours=hours)
    
    # Estraiamo l'identificativo della chiave della CA dal suo certificato per l'AKI
    try:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    except Exception:
        # Fallback se non riusciamo ad estrarlo direttamente
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        )

    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(subject_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + delta)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # --- ESTENSIONI REALI PER I CERTIFICATI FIGLI ---
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_pub), critical=False)
        .add_extension(aki, critical=False)
        # -----------------------------------------------
    )
    if server_san:   # certificati TLS dei server: SAN + serverAuth
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(server_san)]), critical=False)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


# Certificato pseudonimo dell'elettore: Cert(PKv), validita' 24h (giornata di voto)
def issue_voter_cert(ca_key, ca_cert, voter_pub, pseudonym: str):
    return _issue(ca_key, ca_cert, voter_pub, pseudonym, hours=24)


# Certificato della chiave di cifratura della CE: Cert(PK_CE)
def issue_ce_cert(ca_key, ca_cert, ce_pub):
    return _issue(ca_key, ca_cert, ce_pub, "Commissione Elettorale - PK_CE", days=30)


# Certificato di firma di un commissario: Cert(PK_Ci)
def issue_commissioner_cert(ca_key, ca_cert, pub, idx):
    return _issue(ca_key, ca_cert, pub, f"Commissario {idx}", days=30)


# Certificato del Bulletin Board, usato sia per σ_BB sia come cert TLS del server.
def issue_bb_cert(ca_key, ca_cert, bb_pub):
    return _issue(ca_key, ca_cert, bb_pub, "Bulletin Board", days=30,
                  server_san="localhost", eku=[ExtendedKeyUsageOID.SERVER_AUTH])


# Certificato TLS del server di registrazione della Segreteria.
def issue_server_cert(ca_key, ca_cert, srv_pub, cn):
    return _issue(ca_key, ca_cert, srv_pub, cn, days=30,
                  server_san="localhost", eku=[ExtendedKeyUsageOID.SERVER_AUTH])


# Verifica di un certificato rispetto alla Root CA
def verify_signed_by(cert, ca_cert) -> bool:
    """Verifica che `cert` sia stato firmato dalla chiave privata della CA,
    usando la chiave pubblica di `ca_cert` (PKCS#1 v1.5 + SHA-256)."""
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
            )
        return True
    except Exception:
        return False


# Helper PEM (per scrivere i file usati dal modulo ssl)
def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def load_cert_pem(pem: bytes):
    return x509.load_pem_x509_certificate(pem)

def is_cert_valid_now(cert) -> bool:
    now = datetime.datetime.now(_UTC)
    try:
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc
    except AttributeError:          # versioni più vecchie di cryptography
        now = now.replace(tzinfo=None)
        return cert.not_valid_before <= now <= cert.not_valid_after