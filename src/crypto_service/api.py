from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from pydantic import BaseModel, Field

from cryptography.hazmat.primitives import serialization

from crypto_service.certificate_authority import (
    generate_root_ca,
    generate_sub_ca,
    issue_certificate,
)

from crypto_service.helpers import (
    get_authority_key_identifier,
    get_certificate_id,
    get_subject_key_identifier,
    list_cas_from_store,
    list_entities_from_store,
    list_certificates_from_store,
    load_ca_from_store,
    load_entity_public_key_by_common_name,
    load_certificate_from_store,
    save_certificate_to_pem,
)

from crypto_service.validation import (
    can_issue_certificates,
    is_certificate_time_valid,
    validate_certificate_chain,
)


from crypto_service.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    authenticate_user,
    create_access_token,
    get_current_user,
)

CA_STORAGE_DIR = Path("storage/cas")
CERTIFICATE_STORAGE_DIR = Path("storage/certificates")
ENTITY_STORAGE_DIR = Path("storage/entities")


app = FastAPI(
    title="Crypto Service",
    version="0.1.0",
)


############################ AUTHENTICATION ###########################

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int

@app.post(
    "/auth/login",
    response_model=TokenResponse,
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> TokenResponse:
    user = authenticate_user(
        username=form_data.username,
        password=form_data.password,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        username=user.username,
        role=user.role,
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


############################ CREATE ROOT CA ###########################

class CreateRootCARequest(BaseModel): #Model for the request body when creating a root CA
    common_name: str = Field(
        default="Crypto Service Root CA",
        min_length=1,
        max_length=100,
    )


class CreateRootCAResponse(BaseModel): #Model for the response body when creating a root CA
    message: str
    subject: str
    issuer: str
    serial_number: str
    subject_key_identifier: str
    certificate_pem: str



@app.post(
    "/crypto/ca",
    response_model=CreateRootCAResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)],
)
def create_root_ca(request: CreateRootCARequest) -> CreateRootCAResponse:
    try:
        root_ca = generate_root_ca(
            common_name=request.common_name,
            save_to_files=True,
            storage_dir=CA_STORAGE_DIR,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create Root CA.",
        ) from exc

    certificate = root_ca.certificate

    certificate_pem = certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    ).decode("utf-8")

    return CreateRootCAResponse(
        message="Root CA created successfully.",
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=str(certificate.serial_number),
        subject_key_identifier=get_subject_key_identifier(certificate),
        certificate_pem=certificate_pem,
    )


############################# LIST CAs ###########################

class CAListItem(BaseModel):
    subject_key_identifier: str
    subject: str
    issuer: str
    serial_number: str
    ca_type: str


class ListCAsResponse(BaseModel):
    count: int
    cas: list[CAListItem]


@app.get(
    "/crypto/ca",
    response_model=ListCAsResponse,
    dependencies=[Depends(get_current_user)]
)
def list_cas() -> ListCAsResponse:
    cas = list_cas_from_store(base_dir=CA_STORAGE_DIR)

    return ListCAsResponse(
        count=len(cas),
        cas=cas,
    )

############################ CREATE SUB CA ###########################

class CreateSubCARequest(BaseModel):
    issuer_subject_key_identifier: str = Field(
        min_length=1,
        max_length=128,
    )
    common_name: str = Field(
        default="Crypto Service Sub CA",
        min_length=1,
        max_length=100,
    )


class CreateSubCAResponse(BaseModel):
    message: str
    subject: str
    issuer: str
    serial_number: str
    subject_key_identifier: str
    authority_key_identifier: str
    certificate_pem: str


@app.post(
    "/crypto/subca",
    response_model=CreateSubCAResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)],
)
def create_sub_ca(request: CreateSubCARequest) -> CreateSubCAResponse:
    try:
        issuer_ca = load_ca_from_store( # Loads the issuer CA from the store based on the provided Subject Key Identifier
            subject_key_identifier=request.issuer_subject_key_identifier,
            base_dir=CA_STORAGE_DIR,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issuer CA not found.",
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Issuer CA files are missing.",
        ) from exc

    if not is_certificate_time_valid(issuer_ca.certificate): # Checks if the issuer CA certificate is currently valid
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Issuer CA certificate is not currently valid.",
        )

    if not can_issue_certificates(issuer_ca.certificate): # Checks if the issuer CA certificate has the necessary extensions to issue other certificates
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Issuer CA is not allowed to issue certificates.",
        )

    try:
        sub_ca = generate_sub_ca( # Generates a new SubCA based on the issuer CA
            issuer_ca=issuer_ca,
            common_name=request.common_name,
            save_to_files=True,
            storage_dir=CA_STORAGE_DIR,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not create SubCA.",
        ) from exc

    certificate = sub_ca.certificate

    certificate_pem = certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    ).decode("utf-8")

    return CreateSubCAResponse(
        message="SubCA created successfully.",
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=str(certificate.serial_number),
        subject_key_identifier=get_subject_key_identifier(certificate),
        authority_key_identifier=get_authority_key_identifier(certificate),
        certificate_pem=certificate_pem,
    )

############################# LIST ENTITIES ###########################

class EntityListItem(BaseModel):
    common_name: str
    public_key_available: bool


class ListEntitiesResponse(BaseModel):
    count: int
    entities: list[EntityListItem]

@app.get(
    "/crypto/entities",
    response_model=ListEntitiesResponse,
    dependencies=[Depends(get_current_user)],
)
def list_entities() -> ListEntitiesResponse:
    entities = list_entities_from_store(
        base_dir=ENTITY_STORAGE_DIR,
    )

    return ListEntitiesResponse(
        count=len(entities),
        entities=entities,
    )



############################ ISSUE CERTIFICATE ###########################

class IssueCertificateRequest(BaseModel):
    issuer_subject_key_identifier: str = Field(
        min_length=1,
        max_length=128,
    )
    common_name: str = Field(
        min_length=1,
        max_length=100,
    )
    validity_days: int = Field(
        default=365,
        ge=1,
        le=825,
    )


class IssueCertificateResponse(BaseModel):
    message: str
    certificate_id: str
    subject: str
    issuer: str
    serial_number: str
    subject_key_identifier: str
    authority_key_identifier: str
    certificate_pem: str


@app.post(
    "/crypto/issue",
    response_model=IssueCertificateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)],
)
def issue_end_entity_certificate(
    request: IssueCertificateRequest,
) -> IssueCertificateResponse:
    try:
        issuer_ca = load_ca_from_store( # Loads the issuer CA from the store based on the provided Subject Key Identifier
            subject_key_identifier=request.issuer_subject_key_identifier,
            base_dir=CA_STORAGE_DIR,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Issuer CA not found.",
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Issuer CA files are missing.",
        ) from exc

    if not is_certificate_time_valid(issuer_ca.certificate): # Checks if the issuer CA certificate is currently valid
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Issuer CA certificate is not currently valid.",
        )

    if not can_issue_certificates(issuer_ca.certificate): # Checks if the issuer CA certificate has the necessary extensions to issue other certificates
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Issuer CA is not allowed to issue certificates.",
        )

    try:
        subject_public_key = load_entity_public_key_by_common_name( # Loads the public key of the entity for which the certificate is being issued, based on the provided common name
            common_name=request.common_name,
            base_dir=ENTITY_STORAGE_DIR,
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Entity public key file not found for the provided common name.",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid entity public key.",
        ) from exc

    try:
        certificate = issue_certificate(
            issuer_ca=issuer_ca,
            subject_public_key=subject_public_key,
            common_name=request.common_name,
            validity_days=request.validity_days,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not issue certificate.",
        ) from exc

    try:
        save_certificate_to_pem(
            certificate=certificate,
            base_dir=CERTIFICATE_STORAGE_DIR,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Certificate was issued but could not be stored.",
        ) from exc

    certificate_pem = certificate.public_bytes(  # Converts the issued certificate to PEM format for easy storage and transmission
        encoding=serialization.Encoding.PEM,
    ).decode("utf-8")

    certificate_id = get_certificate_id(certificate)

    return IssueCertificateResponse(
        message="Certificate issued successfully.",
        certificate_id=certificate_id,
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=str(certificate.serial_number),
        subject_key_identifier=get_subject_key_identifier(certificate),
        authority_key_identifier=get_authority_key_identifier(certificate),
        certificate_pem=certificate_pem,
    )


############################# LIST CERTIFICATES ###########################

class CertificateListItem(BaseModel):
    certificate_id: str
    subject: str
    issuer: str
    serial_number: str
    certificate_available: bool


class ListCertificatesResponse(BaseModel):
    count: int
    certificates: list[CertificateListItem]

@app.get(
    "/crypto/certificates",
    response_model=ListCertificatesResponse,
    dependencies=[Depends(get_current_user)],
)
def list_certificates() -> ListCertificatesResponse:
    certificates = list_certificates_from_store(
        base_dir=CERTIFICATE_STORAGE_DIR,
    )

    return ListCertificatesResponse(
        count=len(certificates),
        certificates=certificates,
    )

############################ VALIDATE CERTIFICATE ###########################

class ValidateCertificateRequest(BaseModel):
    certificate_id: str = Field(
        min_length=1,
        max_length=128,
    )


class ValidateCertificateResponse(BaseModel):
    valid: bool
    message: str
    certificate_id: str
    subject: str
    issuer: str
    serial_number: str


@app.post(
    "/crypto/validate",
    response_model=ValidateCertificateResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(get_current_user)],
)
def validate_x509_certificate(
    request: ValidateCertificateRequest,
) -> ValidateCertificateResponse:
    try:
        certificate = load_certificate_from_store( # Loads the certificate from the store based on the provided certificate ID
            certificate_id=request.certificate_id,
            base_dir=CERTIFICATE_STORAGE_DIR,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid certificate id.",
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Certificate not found.",
        ) from exc

    try:
        is_valid = validate_certificate_chain( # Validates the provided certificate, ensuring that it is properly signed and trusted
            certificate=certificate,
            ca_store_dir=CA_STORAGE_DIR,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not validate certificate.",
        ) from exc

    message = (
        "Certificate is valid."
        if is_valid
        else "Certificate is not valid."
    )

    return ValidateCertificateResponse(
        valid=is_valid,
        message=message,
        certificate_id=get_certificate_id(certificate),
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=str(certificate.serial_number),
    )

