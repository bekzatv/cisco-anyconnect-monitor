"""HTTPS for the web panel: a self-signed certificate generated on first use."""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import logging
import socket
import ssl
from pathlib import Path

from .config import TLS_DIR

log = logging.getLogger("vpnmon.tls")

CERT_FILE = TLS_DIR / "panel-cert.pem"
KEY_FILE = TLS_DIR / "panel-key.pem"


def local_addresses() -> list[str]:
    """IPv4 addresses of this machine, for the certificate and for showing panel URLs."""
    addrs = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except OSError:
        pass
    return sorted(addrs, key=lambda a: (a.startswith("127."), a))


def ensure_certificate(cert_file: Path = CERT_FILE, key_file: Path = KEY_FILE) -> tuple[Path, Path]:
    if cert_file.exists() and key_file.exists():
        return cert_file, key_file
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    hostname = socket.gethostname()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cisco AnyConnect Monitor"),
    ])
    alt_names: list[x509.GeneralName] = [x509.DNSName(hostname), x509.DNSName("localhost")]
    alt_names += [x509.IPAddress(ipaddress.ip_address(a)) for a in local_addresses()]
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3 * 365))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    log.info("Создан самоподписанный сертификат панели: %s", cert_file)
    return cert_file, key_file


def certificate_info(cert_file: Path = CERT_FILE) -> dict:
    if not cert_file.exists():
        return {}
    der = ssl.PEM_cert_to_DER_cert(cert_file.read_text(encoding="ascii"))
    from cryptography import x509

    cert = x509.load_der_x509_certificate(der)
    fp = hashlib.sha256(der).hexdigest().upper()
    return {
        "sha256": ":".join(fp[i:i + 2] for i in range(0, len(fp), 2)),
        "valid_until": cert.not_valid_after_utc.strftime("%d.%m.%Y"),
        "file": str(cert_file),
    }


def server_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(str(cert_file), str(key_file))
    return ctx
