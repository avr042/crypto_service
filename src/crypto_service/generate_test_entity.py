import argparse
import shutil
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from crypto_service.certificate_authority import generate_private_key
from crypto_service.helpers import slugify


def save_test_entity_keys(
    common_name: str,
    entity_type: str,
    base_dir: Path,
    overwrite: bool,
) -> Path:
    entity_directory = base_dir / f"{entity_type}-{slugify(common_name)}"

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

    return entity_directory


def main():
    parser = argparse.ArgumentParser(
        description="Generate test key pairs for simulated end entities."
    )

    parser.add_argument(
        "common_name",
        help="Common name of the simulated entity, for example api.local.",
    )

    parser.add_argument(
        "--entity-type",
        default="server",
        choices=["server", "client", "device"],
        help="Type of simulated entity.",
    )

    parser.add_argument(
        "--base-dir",
        default="storage/entities",
        help="Directory where test entity keys will be stored.",
    )

    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the entity directory if it already exists.",
    )

    args = parser.parse_args()

    entity_directory = save_test_entity_keys(
        common_name=args.common_name,
        entity_type=args.entity_type,
        base_dir=Path(args.base_dir),
        overwrite=args.overwrite,
    )

    print("Test entity keys generated successfully.")
    print("Directory:", entity_directory)
    print("Private key:", entity_directory / "private_key.pem")
    print("Public key:", entity_directory / "public_key.pem")


if __name__ == "__main__":
    main()