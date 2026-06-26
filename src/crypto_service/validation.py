from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.primitives import hashes

from crypto_service.helpers import (
    get_authority_key_identifier,
    load_ca_index,
    load_certificate_from_pem,
)


def is_certificate_time_valid(certificate: x509.Certificate) -> bool: # Checks if the certificate is currently valid based on its validity period
    now = datetime.now(timezone.utc)

    if certificate.not_valid_before_utc > now:
        return False

    if certificate.not_valid_after_utc < now:
        return False

    return True


def find_issuer_certificate( # Finds the issuer certificate for a given certificate from the CA store
    certificate: x509.Certificate,
    ca_store_dir: str | Path = "storage/cas",
) -> x509.Certificate | None:
    try:
        authority_key_identifier = get_authority_key_identifier(certificate)
    except (ExtensionNotFound, ValueError):
        return None

    ca_store_path = Path(ca_store_dir)
    index = load_ca_index(base_dir=ca_store_path)

    issuer_entry = index["by_subject_key_identifier"].get(
        authority_key_identifier
    )

    if issuer_entry is None:
        return None

    issuer_certificate_path = ca_store_path / issuer_entry["certificate_path"]

    if not issuer_certificate_path.exists():
        return None

    return load_certificate_from_pem(issuer_certificate_path)

def can_issue_certificates(certificate: x509.Certificate) -> bool: # Checks if the certificate can issue other certificates
    try:
        basic_constraints = certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except ExtensionNotFound:
        return False

    if not basic_constraints.ca:
        return False

    try:
        key_usage = certificate.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE
        ).value
    except ExtensionNotFound:
        return False

    if not key_usage.key_cert_sign:
        return False

    return True


def is_certificate_signature_valid( # Checks if the signature of the certificate is valid using the issuer's public key
    certificate: x509.Certificate,
    issuer_certificate: x509.Certificate,
) -> bool:
    issuer_public_key = issuer_certificate.public_key()

    if not isinstance(issuer_public_key, rsa.RSAPublicKey):
        return False

    try:
        issuer_public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False

    return True




def validate_certificate( # Validates a certificate by checking its validity period, issuer, and signature
    certificate: x509.Certificate,
    ca_store_dir: str | Path = "storage/cas",
) -> bool:
    if not is_certificate_time_valid(certificate): # Checks if the certificate is currently valid based on its validity period
        return False

    issuer_certificate = find_issuer_certificate( # Finds the issuer certificate for a given certificate from the CA store
        certificate=certificate,
        ca_store_dir=ca_store_dir,
    )

    if issuer_certificate is None: # If the issuer certificate cannot be found, the certificate is considered invalid
        return False

    if certificate.issuer != issuer_certificate.subject: # Checks if the issuer of the certificate matches the subject of the issuer certificate    
        return False

    if not is_certificate_time_valid(issuer_certificate): # Checks if the issuer certificate is currently valid based on its validity period
        return False

    if not can_issue_certificates(issuer_certificate): # Checks if the issuer certificate has the necessary permissions to issue other certificates
        return False
    
    if not is_certificate_signature_valid( # Checks if the signature of the certificate is valid using the issuer's public key
        certificate=certificate,
        issuer_certificate=issuer_certificate,
    ):
        return False

    return True

def get_certificate_fingerprint(certificate: x509.Certificate) -> str:
    return certificate.fingerprint(hashes.SHA256()).hex()


def same_certificate(
    first_certificate: x509.Certificate,
    second_certificate: x509.Certificate,
) -> bool:
    return (
        get_certificate_fingerprint(first_certificate)
        == get_certificate_fingerprint(second_certificate)
    )


def is_trusted_root_certificate(
    certificate: x509.Certificate,
    ca_store_dir: str | Path = "storage/cas",
) -> bool:
    if certificate.subject != certificate.issuer: # Checks if the certificate is self-signed 
        return False

    issuer_certificate = find_issuer_certificate( # Finds the issuer certificate for a given certificate from the CA store
        certificate=certificate,
        ca_store_dir=ca_store_dir,
    )

    if issuer_certificate is None:  # If the issuer certificate cannot be found, the certificate is not considered a trusted root certificate
        return False

    if not same_certificate(certificate, issuer_certificate): # Checks if the certificate is the same as its issuer certificate
        return False

    return validate_certificate( # Validates the certificate by checking its validity period, issuer, and signature
        certificate=certificate,
        ca_store_dir=ca_store_dir,
    )

def validate_certificate_chain( # Validates a certificate chain by checking each certificate in the chain up to a trusted root certificate
    certificate: x509.Certificate,
    ca_store_dir: str | Path = "storage/cas",
    max_depth: int = 10,
) -> bool:
    current_certificate = certificate
    visited_fingerprints: set[str] = set()

    for _ in range(max_depth):
        current_fingerprint = get_certificate_fingerprint(current_certificate) # Gets the fingerprint of the current certificate to avoid cycles in the chain

        if current_fingerprint in visited_fingerprints:
            return False

        visited_fingerprints.add(current_fingerprint)

        if not validate_certificate(
            certificate=current_certificate,
            ca_store_dir=ca_store_dir,
        ):
            return False

        issuer_certificate = find_issuer_certificate(
            certificate=current_certificate,
            ca_store_dir=ca_store_dir,
        )

        if issuer_certificate is None:
            return False

        if is_trusted_root_certificate(
            certificate=issuer_certificate,
            ca_store_dir=ca_store_dir,
        ):
            return True

        current_certificate = issuer_certificate

    return False