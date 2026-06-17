"""

Condivisione del segreto a soglia (t, n) di Shamir.

Il segreto e' un fattore primo p del modulo RSA della CE: chi conosce p
puo' ricavare q = N/p e quindi la chiave privata. Distribuendo p con Shamir
si evita il single point of failure: servono almeno t commissari su n.

Lo schema lavora nel campo GF(P) con P primo > segreto e > n. Usiamo il
primo di Mersenne M1279 = 2^1279 - 1, comodamente piu' grande di qualunque
fattore primo p (~1024 bit) di un modulo RSA-2048.
"""

import secrets

# Primo di Mersenne 2^1279 - 1 (noto primo, > 2^1024 > p).
PRIME = (1 << 1279) - 1


def split(secret: int, t: int, n: int):
    """Divide secret in n quote con soglia t.
    Ritorna la lista [(i, g(i)) for i in 1..n].

    Polinomio casuale di grado t-1:  g(x) = a_{t-1} x^{t-1} + ... + a_1 x + S (mod P)
    con S = secret (termine noto)."""
    assert 0 < t <= n
    assert secret < PRIME
    # coefficienti casuali a_1..a_{t-1}; a_0 = secret
    coeffs = [secret] + [secrets.randbelow(PRIME) for _ in range(t - 1)]

    def g(x):
        # valutazione di Horner del polinomio in x, mod P
        acc = 0
        for c in reversed(coeffs):
            acc = (acc * x + c) % PRIME
        return acc

    return [(i, g(i)) for i in range(1, n + 1)]


def reconstruct(shares) -> int:
    """Ricostruisce il segreto da >= t quote tramite interpolazione di
    Lagrange valutata in x = 0."""
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        # termine di Lagrange L_j(0) = prod_{m!=j} (-x_m) / (x_j - x_m)  (mod P)
        num, den = 1, 1
        for m, (xm, _) in enumerate(shares):
            if m == j:
                continue
            num = (num * (-xm)) % PRIME
            den = (den * (xj - xm)) % PRIME
        lagrange = (num * pow(den, -1, PRIME)) % PRIME   # inverso modulare
        secret = (secret + yj * lagrange) % PRIME
    return secret
