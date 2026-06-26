import json
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID


def slugify(value: str) -> str:
    value = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value)
    value = value.strip("-")

    return value or "ca"


def get_common_name(certificate: x509.Certificate) -> str:
    common_name_attributes = certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )

    if not common_name_attributes:
        return "unknown-ca"

    return common_name_attributes[0].value


def build_ca_directory_path(
    certificate: x509.Certificate,
    base_dir: str | Path = "storage/cas",
) -> Path:
    common_name = slugify(get_common_name(certificate))
    serial_number = format(certificate.serial_number, "x")[:12]

    return Path(base_dir) / f"{common_name}-{serial_number}"


def load_certificate_from_pem(path: str | Path) -> x509.Certificate:
    certificate_bytes = Path(path).read_bytes()

    return x509.load_pem_x509_certificate(certificate_bytes)


def get_subject_key_identifier(certificate: x509.Certificate) -> str:
    extension = certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    )

    subject_key_identifier = extension.value

    return subject_key_identifier.digest.hex()


def get_authority_key_identifier(certificate: x509.Certificate) -> str:
    extension = certificate.extensions.get_extension_for_oid(
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER
    )

    authority_key_identifier = extension.value

    if authority_key_identifier.key_identifier is None:
        raise ValueError("Certificate does not contain an Authority Key Identifier.")

    return authority_key_identifier.key_identifier.hex()


def load_ca_index(base_dir: str | Path = "storage/cas") -> dict:
    ca_store_path = Path(base_dir)
    index_path = ca_store_path / "index.json"

    if not index_path.exists():
        return {
            "by_subject_key_identifier": {}
        }

    return json.loads(index_path.read_text(encoding="utf-8"))


def save_ca_index(
    index: dict,
    base_dir: str | Path = "storage/cas",
) -> None:
    ca_store_path = Path(base_dir)
    ca_store_path.mkdir(parents=True, exist_ok=True)

    index_path = ca_store_path / "index.json"

    index_path.write_text(
        json.dumps(index, indent=2),
        encoding="utf-8",
    )


def update_ca_index(
    certificate: x509.Certificate,
    ca_directory: Path,
    base_dir: str | Path = "storage/cas",
) -> None:
    ca_store_path = Path(base_dir)

    index = load_ca_index(base_dir=ca_store_path)

    subject_key_identifier = get_subject_key_identifier(certificate)

    certificate_path = ca_directory / "certificate.pem"
    private_key_path = ca_directory / "private_key.pem"

    relative_certificate_path = certificate_path.relative_to(ca_store_path)
    relative_private_key_path = private_key_path.relative_to(ca_store_path)
    relative_ca_directory = ca_directory.relative_to(ca_store_path)

    index["by_subject_key_identifier"][subject_key_identifier] = {
        "subject": certificate.subject.rfc4514_string(),
        "serial_number": str(certificate.serial_number),
        "directory": str(relative_ca_directory),
        "certificate_path": str(relative_certificate_path),
        "private_key_path": str(relative_private_key_path),
    }

    save_ca_index(
        index=index,
        base_dir=ca_store_path,
    )


def save_ca_to_pem(
    private_key: rsa.RSAPrivateKey,
    certificate: x509.Certificate,
    base_dir: str | Path = "storage/cas",
) -> Path:
    ca_directory = build_ca_directory_path(
        certificate=certificate,
        base_dir=base_dir,
    )

    ca_directory.mkdir(parents=True, exist_ok=True)

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    certificate_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    )

    private_key_path = ca_directory / "private_key.pem"
    certificate_path = ca_directory / "certificate.pem"

    private_key_path.write_bytes(private_key_bytes)
    certificate_path.write_bytes(certificate_bytes)

    update_ca_index(
        certificate=certificate,
        ca_directory=ca_directory,
        base_dir=base_dir,
    )

    return ca_directory