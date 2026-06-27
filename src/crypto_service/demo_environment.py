import argparse
import shutil
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from crypto_service.certificate_authority import (
    generate_private_key,
    generate_root_ca,
    generate_sub_ca,
    issue_certificate,
)
from crypto_service.helpers import (
    get_subject_key_identifier,
    save_certificate_to_pem,
    slugify,
)
from crypto_service.validation import validate_certificate_chain


CA_STORAGE_DIR = Path("storage/cas")
CERTIFICATE_STORAGE_DIR = Path("storage/certificates")
ENTITY_STORAGE_DIR = Path("storage/entities")


def save_entity_key_pair(
    common_name: str,
    entity_type: str,
    base_dir: Path = ENTITY_STORAGE_DIR,
    overwrite: bool = False,
):
    entity_directory = base_dir / slugify(common_name)

    if entity_directory.exists():
        if not overwrite:
            raise FileExistsError(
                f"Entity directory already exists: {entity_directory}"
            )

        shutil.rmtree(entity_directory)

    entity_directory.mkdir(parents=True, exist_ok=True)

    private_key = generate_private_key()
    public_key = private_key.public_key()

    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    (entity_directory / "private_key.pem").write_bytes(private_key_bytes)
    (entity_directory / "public_key.pem").write_bytes(public_key_bytes)

    return {
        "common_name": common_name,
        "entity_type": entity_type,
        "directory": entity_directory,
        "private_key": private_key,
        "public_key": public_key,
    }


def create_demo_environment(
    reset_storage: bool = True,
    issue_entity_certificates: bool = False,
):
    if reset_storage and Path("storage").exists():
        shutil.rmtree("storage")

    root_ca = generate_root_ca(
        common_name="Crypto Service Root CA",
        save_to_files=True,
        storage_dir=CA_STORAGE_DIR,
    )

    tls_sub_ca = generate_sub_ca(
        issuer_ca=root_ca,
        common_name="Crypto Service TLS Sub CA",
        save_to_files=True,
        storage_dir=CA_STORAGE_DIR,
    )

    client_sub_ca = generate_sub_ca(
        issuer_ca=root_ca,
        common_name="Crypto Service Client Sub CA",
        save_to_files=True,
        storage_dir=CA_STORAGE_DIR,
    )

    entities = [
        save_entity_key_pair(
            common_name="api.local",
            entity_type="server",
            overwrite=True,
        ),
        save_entity_key_pair(
            common_name="admin.local",
            entity_type="server",
            overwrite=True,
        ),
        save_entity_key_pair(
            common_name="alice.client",
            entity_type="client",
            overwrite=True,
        ),
    ]

    issued_certificates = []

    if issue_entity_certificates:
        for entity in entities:
            issuer_ca = (
                client_sub_ca
                if entity["entity_type"] == "client"
                else tls_sub_ca
            )

            certificate = issue_certificate(
                issuer_ca=issuer_ca,
                subject_public_key=entity["public_key"],
                common_name=entity["common_name"],
            )

            save_certificate_to_pem(
                certificate=certificate,
                base_dir=CERTIFICATE_STORAGE_DIR,
            )

            issued_certificates.append(certificate)

    return {
        "root_ca": root_ca,
        "sub_cas": [tls_sub_ca, client_sub_ca],
        "entities": entities,
        "issued_certificates": issued_certificates,
    }


def print_demo_summary(demo_environment: dict) -> None:
    root_ca = demo_environment["root_ca"]
    sub_cas = demo_environment["sub_cas"]
    entities = demo_environment["entities"]
    issued_certificates = demo_environment["issued_certificates"]

    print("Demo environment created successfully.")
    print()

    print("Root CA")
    print("Subject:", root_ca.certificate.subject.rfc4514_string())
    print("SKI:", get_subject_key_identifier(root_ca.certificate))
    print()

    print("SubCAs")
    for sub_ca in sub_cas:
        print("-", sub_ca.certificate.subject.rfc4514_string())
        print("  Issuer:", sub_ca.certificate.issuer.rfc4514_string())
        print("  SKI:", get_subject_key_identifier(sub_ca.certificate))
        print(
            "  Chain valid:",
            validate_certificate_chain(sub_ca.certificate),
        )

    print()

    print("Entities")
    for entity in entities:
        print("-", entity["common_name"])
        print("  Type:", entity["entity_type"])
        print("  Directory:", entity["directory"])

    print()

    if issued_certificates:
        print("Issued certificates")
        for certificate in issued_certificates:
            print("-", certificate.subject.rfc4514_string())
            print("  Issuer:", certificate.issuer.rfc4514_string())
            print("  Chain valid:", validate_certificate_chain(certificate))


def main():
    parser = argparse.ArgumentParser(
        description="Create a local demo PKI environment."
    )

    parser.add_argument(
        "--reset-storage",
        action="store_true",
        help="Delete storage/ before creating the demo environment.",
    )

    parser.add_argument(
        "--no-certificates",
        action="store_true",
        help="Create entity keys but do not issue certificates.",
    )

    args = parser.parse_args()

    demo_environment = create_demo_environment(
        reset_storage=args.reset_storage,
        issue_entity_certificates=not args.no_certificates,
    )

    print_demo_summary(demo_environment)


if __name__ == "__main__":
    main()