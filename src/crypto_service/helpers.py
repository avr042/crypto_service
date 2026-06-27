import json
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtensionOID, NameOID


def slugify(value: str) -> str: # Converts a string into a slug format suitable for directory names
    value = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value)
    value = value.strip("-")

    return value or "ca"


def get_common_name(certificate: x509.Certificate) -> str: # Retrieves the Common Name (CN) from a certificate's subject
    common_name_attributes = certificate.subject.get_attributes_for_oid(
        NameOID.COMMON_NAME
    )

    if not common_name_attributes:
        return "unknown-ca"

    return common_name_attributes[0].value


def build_ca_directory_path(  # Builds a directory path for a CA based on its common name and serial number
    certificate: x509.Certificate,
    base_dir: str | Path = "storage/cas",
) -> Path:
    common_name = slugify(get_common_name(certificate))
    serial_number = format(certificate.serial_number, "x")[:12]

    return Path(base_dir) / f"{common_name}-{serial_number}"


def load_certificate_from_pem(path: str | Path) -> x509.Certificate: # Loads a x509 certificate from a PEM file
    certificate_bytes = Path(path).read_bytes()

    return x509.load_pem_x509_certificate(certificate_bytes)


def get_subject_key_identifier(certificate: x509.Certificate) -> str: # Retrieves the Subject Key Identifier from a certificate
    extension = certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    )

    subject_key_identifier = extension.value

    return subject_key_identifier.digest.hex()


def get_authority_key_identifier(certificate: x509.Certificate) -> str: # Retrieves the Authority Key Identifier from a certificate
    extension = certificate.extensions.get_extension_for_oid(
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER
    )

    authority_key_identifier = extension.value

    if authority_key_identifier.key_identifier is None:
        raise ValueError("Certificate does not contain an Authority Key Identifier.")

    return authority_key_identifier.key_identifier.hex()


def load_ca_index(base_dir: str | Path = "storage/cas") -> dict: # Loads the CA index from a JSON file in the specified base directory
    ca_store_path = Path(base_dir)
    index_path = ca_store_path / "index.json"

    if not index_path.exists():
        return {
            "by_subject_key_identifier": {}
        }

    return json.loads(index_path.read_text(encoding="utf-8"))


def save_ca_index( # Saves the CA index to a JSON file in the specified base directory
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


def update_ca_index( # Updates the CA index with a new CA entry based on the provided certificate and its storage directory
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
    "issuer": certificate.issuer.rfc4514_string(),
    "serial_number": str(certificate.serial_number),
    "directory": str(relative_ca_directory),
    "certificate_path": str(relative_certificate_path),
    "private_key_path": str(relative_private_key_path),
    }

    save_ca_index(
        index=index,
        base_dir=ca_store_path,
    )


def save_ca_to_pem( # Saves the private key and certificate of a CA to PEM files in a structured directory
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

def load_private_key_from_pem(path: str | Path) -> rsa.RSAPrivateKey: # Loads an RSA private key from a PEM file
    private_key_bytes = Path(path).read_bytes()

    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None,
    )

    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise ValueError("The private key is not an RSA private key.")

    return private_key

def load_public_key_from_pem(path_or_pem: str | Path) -> rsa.RSAPublicKey:
    if isinstance(path_or_pem, Path) or Path(str(path_or_pem)).exists():
        public_key_bytes = Path(path_or_pem).read_bytes()
    else:
        public_key_bytes = str(path_or_pem).encode("utf-8")

    public_key = serialization.load_pem_public_key(
        public_key_bytes,
    )

    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ValueError("The public key is not an RSA public key.")

    return public_key

def load_entity_public_key_by_common_name(
    common_name: str,
    base_dir: str | Path = "storage/entities",
) -> rsa.RSAPublicKey:
    entity_directory = Path(base_dir) / slugify(common_name)
    public_key_path = entity_directory / "public_key.pem"

    if not public_key_path.exists():
        raise FileNotFoundError("Entity public key file not found.")

    return load_public_key_from_pem(public_key_path)

def load_ca_from_store( # Loads a CA from the store based on its Subject Key Identifier
    subject_key_identifier: str,
    base_dir: str | Path = "storage/cas",
):
    from crypto_service.certificate_authority import CertificateAuthority

    ca_store_path = Path(base_dir)

    index = load_ca_index(base_dir=ca_store_path)

    ca_entry = index["by_subject_key_identifier"].get(
        subject_key_identifier
    )

    if ca_entry is None:
        raise ValueError("CA not found in store.")

    certificate_path = ca_store_path / ca_entry["certificate_path"]
    private_key_path = ca_store_path / ca_entry["private_key_path"]

    if not certificate_path.exists():
        raise FileNotFoundError("CA certificate file not found.")

    if not private_key_path.exists():
        raise FileNotFoundError("CA private key file not found.")

    certificate = load_certificate_from_pem(certificate_path)
    private_key = load_private_key_from_pem(private_key_path)

    return CertificateAuthority(
        private_key=private_key,
        certificate=certificate,
    )


################# Certificate storage functions ####################

def build_certificate_directory_path( # Builds a directory path for a certificate based on its common name and serial number
    certificate: x509.Certificate,
    base_dir: str | Path = "storage/certificates",
) -> Path:
    common_name = slugify(get_common_name(certificate))
    serial_number = format(certificate.serial_number, "x")[:12]

    return Path(base_dir) / f"{common_name}-{serial_number}"


def load_certificate_index( # Loads the certificate index from a JSON file in the specified base directory
    base_dir: str | Path = "storage/certificates",
) -> dict:
    certificate_store_path = Path(base_dir)
    index_path = certificate_store_path / "index.json"

    if not index_path.exists():
        return {"certificates": {}}

    return json.loads(index_path.read_text(encoding="utf-8"))


def save_certificate_index( # Saves the certificate index to a JSON file in the specified base directory
    index: dict,
    base_dir: str | Path = "storage/certificates",
) -> None:
    certificate_store_path = Path(base_dir)
    certificate_store_path.mkdir(parents=True, exist_ok=True)

    index_path = certificate_store_path / "index.json"

    index_path.write_text(
        json.dumps(index, indent=2),
        encoding="utf-8",
    )

def get_certificate_id(certificate: x509.Certificate) -> str:
    return format(certificate.serial_number, "x")


def save_certificate_to_pem( # Saves a certificate to a PEM file in a structured directory and updates the certificate index
    certificate: x509.Certificate,
    base_dir: str | Path = "storage/certificates",
) -> Path:
    certificate_directory = build_certificate_directory_path(
        certificate=certificate,
        base_dir=base_dir,
    )

    certificate_directory.mkdir(parents=True, exist_ok=True)

    certificate_path = certificate_directory / "certificate.pem"

    certificate_bytes = certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    )

    certificate_path.write_bytes(certificate_bytes)

    certificate_store_path = Path(base_dir)

    relative_certificate_path = certificate_path.relative_to(
        certificate_store_path
    )
    relative_certificate_directory = certificate_directory.relative_to(
        certificate_store_path
    )

    certificate_id = get_certificate_id(certificate)

    index = load_certificate_index(base_dir=certificate_store_path)

    index["certificates"][certificate_id] = {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_number": str(certificate.serial_number),
        "directory": str(relative_certificate_directory),
        "certificate_path": str(relative_certificate_path),
    }

    save_certificate_index(
        index=index,
        base_dir=certificate_store_path,
    )

    return certificate_directory


def load_certificate_from_store(
    certificate_id: str,
    base_dir: str | Path = "storage/certificates",
) -> x509.Certificate:
    normalized_certificate_id = certificate_id.strip().lower()

    if not re.fullmatch(r"[0-9a-f]+", normalized_certificate_id):
        raise ValueError("Invalid certificate id.")

    certificate_store_path = Path(base_dir)

    index = load_certificate_index(
        base_dir=certificate_store_path,
    )

    certificate_entry = index["certificates"].get(
        normalized_certificate_id
    )

    if certificate_entry is None:
        raise FileNotFoundError("Certificate not found in store.")

    certificate_path = certificate_store_path / certificate_entry["certificate_path"]

    if not certificate_path.exists():
        raise FileNotFoundError("Certificate file not found.")

    return load_certificate_from_pem(certificate_path)


################## List generartion functions ####################

def list_cas_from_store( # Lists all CAs from the store, returning their details in a structured format
    base_dir: str | Path = "storage/cas",
) -> list[dict]:
    index = load_ca_index(base_dir=base_dir)

    cas = []

    for subject_key_identifier, ca_entry in index[
        "by_subject_key_identifier"
    ].items():
        subject = ca_entry.get("subject")
        issuer = ca_entry.get("issuer")

        ca_type = "root_ca" if subject == issuer else "sub_ca"

        cas.append(
            {
                "subject_key_identifier": subject_key_identifier,
                "subject": subject,
                "issuer": issuer,
                "serial_number": ca_entry.get("serial_number"),
                "ca_type": ca_type,
            }
        )

    return cas

def list_entities_from_store(
    base_dir: str | Path = "storage/entities",
) -> list[dict]:
    entity_store_path = Path(base_dir)

    if not entity_store_path.exists():
        return []

    entities = []

    for entity_directory in sorted(entity_store_path.iterdir()):
        if not entity_directory.is_dir():
            continue

        public_key_path = entity_directory / "public_key.pem"

        entities.append(
            {
                "common_name": entity_directory.name,
                "public_key_available": public_key_path.exists(),
            }
        )

    return entities


def list_certificates_from_store(
    base_dir: str | Path = "storage/certificates",
) -> list[dict]:
    certificate_store_path = Path(base_dir)

    index = load_certificate_index(
        base_dir=certificate_store_path,
    )

    certificates = []

    for certificate_id, certificate_entry in sorted(
        index["certificates"].items()
    ):
        certificate_path = certificate_store_path / certificate_entry[
            "certificate_path"
        ]

        certificates.append(
            {
                "certificate_id": certificate_id,
                "subject": certificate_entry.get("subject"),
                "issuer": certificate_entry.get("issuer"),
                "serial_number": certificate_entry.get("serial_number"),
                "certificate_available": certificate_path.exists(),
            }
        )

    return certificates