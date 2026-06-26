from crypto_service.certificate_authority import (
    generate_private_key,
    generate_root_ca,
    generate_sub_ca,
    issue_certificate,
)

from crypto_service.validation import validate_certificate_chain

def main():
    root_ca = generate_root_ca()
    sub_ca = generate_sub_ca(root_ca)

    #In a real-world scenario, the end-entity  keys would be generated and managed by the end-entity itself (e.g., a server or client)
    end_entity_private_key = generate_private_key()
    end_entity_public_key = end_entity_private_key.public_key()

    end_entity_certificate = issue_certificate(
        issuer_ca=sub_ca,
        subject_public_key=end_entity_public_key,
        common_name="api.local",
    )

    print("Root CA")
    print("Subject:", root_ca.certificate.subject)
    print("Issuer:", root_ca.certificate.issuer)

    print()

    print("SubCA")
    print("Subject:", sub_ca.certificate.subject)
    print("Issuer:", sub_ca.certificate.issuer)

    print()

    print("End Entity Certificate")
    print("Subject:", end_entity_certificate.subject)
    print("Issuer:", end_entity_certificate.issuer)

    print(
    "End Entity certificate valid:",
    validate_certificate_chain(end_entity_certificate),
    )

    print(
        "SubCA certificate valid:",
        validate_certificate_chain(sub_ca.certificate),
    )


if __name__ == "__main__":
    main()