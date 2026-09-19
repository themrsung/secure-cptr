"""TLS material for the cptr server.

cptr serves credentials, terminal I/O and workspace contents, none of which
may travel in plain text. On first run we provision a certificate into
`~/.cptr/certs/` and keep reusing it:

1. If `mkcert` is installed, use it — the certificate chains to a CA already
   in the system trust store, so browsers show no warning.
2. Otherwise fall back to a self-signed certificate generated with
   `cryptography` (already a dependency). Browsers show an interstitial the
   user has to accept once.

Certificates are regenerated automatically once they are within
`RENEW_BEFORE_DAYS` of expiry.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import shutil
import subprocess
from pathlib import Path

from cptr.env import DATA_DIR

logger = logging.getLogger("cptr.tls")

CERT_DIR = DATA_DIR / "certs"
CERT_FILE = CERT_DIR / "cert.pem"
KEY_FILE = CERT_DIR / "key.pem"

VALIDITY_DAYS = 825  # ~27 months, the maximum many clients accept
RENEW_BEFORE_DAYS = 30

# Names the certificate must cover for local and LAN use.
DEFAULT_HOSTS = ("localhost", "127.0.0.1", "::1")


def _lan_addresses() -> list[str]:
    """Best-effort list of this host's own IPv4 addresses."""
    import socket

    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(info[4][0])
    except Exception:
        pass
    try:
        # Does not actually send traffic; reveals the outbound interface IP.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            found.add(s.getsockname()[0])
    except Exception:
        pass
    return sorted(found)


def _hostnames(extra: list[str] | None = None) -> list[str]:
    names = list(DEFAULT_HOSTS)
    for host in _lan_addresses() + list(extra or []):
        if host and host not in names:
            names.append(host)
    return names


def _expiry(path: Path) -> dt.datetime | None:
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(path.read_bytes())
        return cert.not_valid_after_utc
    except Exception:
        return None


def _still_valid(hosts: list[str]) -> bool:
    """True when the stored certificate is usable and covers `hosts`."""
    if not (CERT_FILE.exists() and KEY_FILE.exists()):
        return False
    expiry = _expiry(CERT_FILE)
    if expiry is None:
        return False
    if expiry - dt.datetime.now(dt.timezone.utc) < dt.timedelta(days=RENEW_BEFORE_DAYS):
        logger.info("TLS certificate is near expiry; regenerating")
        return False
    try:
        from cryptography import x509
        from cryptography.x509.oid import ExtensionOID

        cert = x509.load_pem_x509_certificate(CERT_FILE.read_bytes())
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        covered = {str(n) for n in san.get_values_for_type(x509.DNSName)}
        covered |= {str(n) for n in san.get_values_for_type(x509.IPAddress)}
        missing = [h for h in hosts if h not in covered]
        if missing:
            logger.info("TLS certificate is missing names %s; regenerating", missing)
            return False
    except Exception:
        return False
    return True


def _generate_with_mkcert(hosts: list[str]) -> bool:
    mkcert = shutil.which("mkcert")
    if not mkcert:
        return False
    try:
        subprocess.run([mkcert, "-install"], check=True, capture_output=True, timeout=60)
        subprocess.run(
            [mkcert, "-cert-file", str(CERT_FILE), "-key-file", str(KEY_FILE), *hosts],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except Exception as exc:
        logger.warning("mkcert failed (%s); falling back to a self-signed certificate", exc)
        return False
    logger.info("Provisioned a locally-trusted TLS certificate with mkcert")
    return True


def _generate_self_signed(hosts: list[str]) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cptr local")])

    alt_names: list[x509.GeneralName] = []
    for host in hosts:
        try:
            alt_names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            alt_names.append(x509.DNSName(host))

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    logger.info("Generated a self-signed TLS certificate (browsers will warn once)")


def ensure_certificate(extra_hosts: list[str] | None = None) -> tuple[Path, Path]:
    """Return `(cert_path, key_path)`, provisioning them if needed."""
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CERT_DIR.chmod(0o700)
    except OSError:
        pass

    hosts = _hostnames(extra_hosts)
    if not _still_valid(hosts):
        if not _generate_with_mkcert(hosts):
            _generate_self_signed(hosts)
        try:
            KEY_FILE.chmod(0o600)
            CERT_FILE.chmod(0o644)
        except OSError:
            pass

    return CERT_FILE, KEY_FILE


def is_locally_trusted() -> bool:
    """True when the stored certificate was issued by a trusted local CA."""
    try:
        from cryptography import x509

        cert = x509.load_pem_x509_certificate(CERT_FILE.read_bytes())
        return cert.issuer != cert.subject
    except Exception:
        return False
