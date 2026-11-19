"""
Self-Signed TLS Development Certificate Generator.
Uses Python cryptography library to generate an RSA 2048-bit key and X.509 certificate
with Subject Alternative Names (SAN) for localhost and 127.0.0.1.
"""

import os
import sys
import ipaddress
from datetime import datetime, timedelta, timezone

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    print("[ERROR] 'cryptography' library is not installed. Run: pip install cryptography")
    sys.exit(1)


def generate_certificate(
    cert_dir=None,
    cert_name="cert.pem",
    key_name="key.pem",
    valid_days=365,
    common_name="localhost"
):
    """Generates an RSA-2048 private key and X.509 v3 TLS certificate."""
    if cert_dir is None:
        cert_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "certs")

    os.makedirs(cert_dir, exist_ok=True)
    cert_path = os.path.join(cert_dir, cert_name)
    key_path = os.path.join(cert_dir, key_name)

    print(f"[*] Generating 2048-bit RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Write private key (PEM format, unencrypted for local dev)
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    print(f"[+] Private key written to: {key_path}")

    # Build Subject and Issuer (self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "State"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "University"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TLS Web App Monitoring System"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Capstone SOC Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    # Subject Alternative Names (SAN) for localhost and loopback IPs
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName("127.0.0.1"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ])

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(san, critical=False)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False
        )
        .sign(private_key, hashes.SHA256())
    )

    # Write Certificate (PEM format)
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] TLS Certificate written to: {cert_path}")
    print(f"[+] Valid for: {valid_days} days | SAN: localhost, 127.0.0.1, ::1")
    print(f"[+] SHA-256 Fingerprint: {cert.fingerprint(hashes.SHA256()).hex()}")
    return cert_path, key_path


if __name__ == "__main__":
    generate_certificate()

