"""

Ogni messaggio: 4 byte big-endian con la lunghezza, poi il payload JSON
(UTF-8). I valori binari (firme, certificati, ciphertext) viaggiano in
base64 dentro il JSON. Su questi socket gira TLS reale (modulo ssl).
"""

import json
import base64
import struct
import ssl
import socket
import threading

# Cache dei contesti TLS lato client: create_default_context rilegge e
# riparsa il certificato della CA a ogni chiamata. Riusare un unico contesto
# per ciascun trust anchor elimina quel costo e abilita la session resumption.
_ctx_cache = {}
_ctx_lock = threading.Lock()


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode())


def send_msg(sock, obj: dict):
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack(">I", len(payload)) + payload)


def _recvall(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connessione chiusa")
        buf += chunk
    return buf


def recv_msg(sock) -> dict:
    (length,) = struct.unpack(">I", _recvall(sock, 4))
    return json.loads(_recvall(sock, length).decode("utf-8"))


def _client_context(ca_cert_path):
    """Contesto TLS client che si fida solo della Root CA."""
    with _ctx_lock:
        ctx = _ctx_cache.get(ca_cert_path)
        if ctx is None:
            ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                             cafile=ca_cert_path)
            ctx.check_hostname = True
            _ctx_cache[ca_cert_path] = ctx
        return ctx


def tls_client_connect(host, port, ca_cert_path):
    """Apre una connessione TLS reale verso un server, validando il suo
    certificato rispetto al trust anchor (root CA) e l'hostname."""
    ctx = _client_context(ca_cert_path)
    raw = socket.create_connection((host, port))
    return ctx.wrap_socket(raw, server_hostname=host)
