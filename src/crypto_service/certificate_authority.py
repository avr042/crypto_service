from pathlib import Path
from datetime import datetime, timedelta, timezone

from crypto_service.helpers import save_ca_to_pem

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization

from dataclasses import dataclass

@dataclass
class CertificateAuthority: 
    private_key: rsa.RSAPrivateKey
    certificate: x509.Certificate


def generate_private_key(): #Create the private key using RSA, ECDSA, or EdDSA algorithms
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    ) #RSA private key generation

    #private_key = ec.generate_private_key(ec.SECP256R1())   #ECDSA private key generation

    #private_key = ed25519.Ed25519PrivateKey.generate() #EdDSA private key generation

    return private_key

###################### root CA generation functions ######################


def generate_root_ca_certificate(
    private_key,
    common_name: str = "Crypto Service Root CA",
): #Create a x509 root CA certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    issuer = subject #In root CA, the issuer is the same as the subject

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650)) #Ten-year validity period for the root CA certificate
        .add_extension(
            x509.BasicConstraints(
                ca=True, #Indicates that this certificate is a CA, Sub CA (True) or End Entity (False)
                path_length=None, #Indicates the maximum number of levels of SubCAs. None means no limit. 0 means it can only emit end-entity certificates.
            ),
            critical=True, #Indicates that this extension must be understood by the certificate user. If not, the certificate should be rejected. 
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, #Indicates that the key can be used for digital signatures. 
                content_commitment=False, #Indicates that the key can be used for content commitment (big guarantee of the data integrity).
                key_encipherment=False, #Indicates that the key can be used for key encipherment (encrypting keys).
                data_encipherment=False, #Indicates that the key can be used for data encipherment (encrypting data).
                key_agreement=False, #Indicates that the key can be used for key agreement (establishing a shared secret).
                encipher_only=False, #Indicates that the key can be used for enciphering only (when used in conjunction with key agreement).
                decipher_only=False, #Indicates that the key can be used for deciphering only (when used in conjunction with key agreement).
                key_cert_sign=True, #Indicates that the key can be used for signing certificates (True in root CAs and Sub CAs).
                crl_sign=True, #Indicates that the key can be used for signing certificate revocation lists (CRLs).
            ),
            critical=True, #Indicates that this extension must be understood by the certificate user. If not, the certificate should be rejected.
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key( #Subject identifier
                private_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key( #Issuer identifier
                private_key.public_key()
            ),
            critical=False,
        )
        .sign(
            private_key=private_key,
            algorithm=hashes.SHA256(), #Hash algorithm used for signing. None for EdDSA keys, as they have a fixed hash algorithm.
        )
    )

    return certificate

def generate_root_ca(
    common_name: str = "Crypto Service Root CA",
    save_to_files: bool = True,
    storage_dir: str | Path = "storage/cas",
) -> CertificateAuthority:
    private_key = generate_private_key()
    certificate = generate_root_ca_certificate(private_key, common_name)

    root_ca = CertificateAuthority(
        private_key=private_key,
        certificate=certificate,
    )

    if save_to_files:
        save_ca_to_pem(
            private_key=root_ca.private_key,
            certificate=root_ca.certificate,
            base_dir=storage_dir,
        )

    return root_ca

####################### sub CA generation functions ######################

def generate_sub_ca_certificate( #Create a x509 sub CA certificate signed by the root CA
    sub_ca_private_key,
    issuer_ca: CertificateAuthority,
    common_name: str = "Crypto Service Sub CA",
    validity_days: int = 1825,
):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    issuer = issuer_ca.certificate.subject #The issuer of the sub CA certificate is the subject of the root CA certificate

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(sub_ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=0, #Indicates that this sub CA can only issue end-entity certificates, not other sub CAs
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                sub_ca_private_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_ca.certificate.public_key()
            ),
            critical=False,
        )
        .sign(
            private_key=issuer_ca.private_key, #Sign the sub CA certificate with the root CA's private key
            algorithm=hashes.SHA256(),
        )
    )

    return certificate

def generate_sub_ca(
    issuer_ca: CertificateAuthority,
    common_name: str = "Crypto Service Sub CA",
    save_to_files: bool = True,
    storage_dir: str | Path = "storage/cas",
) -> CertificateAuthority:
    sub_ca_private_key = generate_private_key()

    sub_ca_certificate = generate_sub_ca_certificate(
        sub_ca_private_key=sub_ca_private_key,
        issuer_ca=issuer_ca,
        common_name=common_name,
    )

    sub_ca = CertificateAuthority(
        private_key=sub_ca_private_key,
        certificate=sub_ca_certificate,
    )

    if save_to_files:
        save_ca_to_pem(
            private_key=sub_ca.private_key,
            certificate=sub_ca.certificate,
            base_dir=storage_dir,
        )

    return sub_ca

######################## certificate issue and validation functions ######################


def issue_certificate(
    issuer_ca: CertificateAuthority,
    subject_public_key,
    common_name: str,
    validity_days: int = 365,
) -> x509.Certificate:
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    issuer = issuer_ca.certificate.subject
    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(subject_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(
            x509.BasicConstraints(
                ca=False, #Indicates that this certificate is an end-entity certificate, not a CA certificate
                path_length=None,
            ),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False, #Indicates that the key cannot be used for signing certificates (False in end-entity certificates).
                crl_sign=False, #Indicates that the key cannot be used for signing CRLs (False in end-entity certificates).
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                subject_public_key
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_ca.certificate.public_key()
            ),
            critical=False,
        )
        .sign(
            private_key=issuer_ca.private_key,
            algorithm=hashes.SHA256(),
        )
    )

    return certificate