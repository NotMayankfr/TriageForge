"""
Generates valid and expired TLS certificates for TriageForge testing.
"""

import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generate_key_and_cert(out_dir: Path, name: str, days_valid: int = 365, is_expired: bool = False):
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Washington"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TriageForge Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, "triageforge.local"),
    ])

    now = datetime.now(timezone.utc)
    if is_expired:
        not_before = now - timedelta(days=90)
        not_after = now - timedelta(days=30)  # Expired 30 days ago
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=days_valid)

    alt_names = [
        x509.DNSName("localhost"),
        x509.DNSName("triageforge.local"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName(alt_names),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / f"{name}.key"
    cert_path = out_dir / f"{name}.crt"

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated {name}: {cert_path} (Valid from {not_before.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')})")


if __name__ == "__main__":
    certs_dir = Path(__file__).resolve().parent
    generate_key_and_cert(certs_dir, "valid", days_valid=365, is_expired=False)
    generate_key_and_cert(certs_dir, "expired", days_valid=60, is_expired=True)

    # By default, copy valid to active
    import shutil
    shutil.copyfile(certs_dir / "valid.crt", certs_dir / "active.crt")
    shutil.copyfile(certs_dir / "valid.key", certs_dir / "active.key")
    print("Default active cert initialized to valid.crt")
