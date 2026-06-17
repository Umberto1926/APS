"""
crypto_utils.py
Primitive crittografiche di base usate da tutto il protocollo.

  - RSA a chiave pubblica (cryptography / pyca);
  - cifratura RSA-OAEP con MGF1-SHA256 (CPA-sicuro, §2.2.1);
  - firme RSA-PSS + SHA-256 in hash-and-sign (§2.2.2);
  - i certificati X.509 sono firmati altrove con PKCS#1 v1.5 + SHA-256
    (default del formato X.509).
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

# Esponente pubblico standard e = 65537
PUBLIC_EXPONENT = 65537


# Generazione delle chiavi
def gen_rsa(bits: int = 2048):
    """Genera una coppia RSA. 2048 bit per elettori/CE/BB """
    return rsa.generate_private_key(public_exponent=PUBLIC_EXPONENT, key_size=bits)


# Hash
def sha256(data: bytes) -> bytes:
    """SHA-256 di una sequenza di byte (digest a 256 bit)."""
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


# Serializzazione chiavi
def pubkey_der(public_key) -> bytes:
    """Serializza una chiave pubblica in DER (SubjectPublicKeyInfo).
    Usata per calcolare il token = SHA-256(PKv) in modo deterministico."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def privkey_pem(private_key) -> bytes:
    """Serializza una chiave privata in PEM (per i file usati dal modulo ssl/TLS)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


# Cifratura RSA-OAEP  
_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def oaep_encrypt(public_key, plaintext: bytes) -> bytes:
    """Cifra con RSA-OAEP. Il seed casuale rende due cifrature dello stesso
    voto diverse tra loro: la preferenza non e' identificabile."""
    return public_key.encrypt(plaintext, _OAEP)


def oaep_decrypt(private_key, ciphertext: bytes) -> bytes:
    """Decifra con RSA-OAEP usando la chiave privata della CE."""
    return private_key.decrypt(ciphertext, _OAEP)


# Firme RSA-PSS  (autenticita' e integrita', §2.2.2)
_PSS = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def pss_sign(private_key, message: bytes) -> bytes:
    """Firma hash-and-sign: la libreria calcola H(message) con SHA-256 e
    applica RSA-PSS (salt casuale, firma non deterministica)."""
    return private_key.sign(message, _PSS, hashes.SHA256())


def pss_verify(public_key, signature: bytes, message: bytes) -> bool:
    """Verifica una firma PSS. Ritorna True/False senza sollevare eccezioni."""
    try:
        public_key.verify(signature, message, _PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False
