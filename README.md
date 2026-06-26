# Crypto Service

## Objetivo

Desarrollo de una aplicación o microservicio que permita realizar operaciones criptográficas básicas basadas en criptografía asimétrica, PKI y certificados X.509.

El proyecto forma parte de una prueba técnica orientada al desarrollo de una aplicación cibersegura.

## Funcionalidades previstas

- Generar una entidad certificadora raíz.
- Generar una entidad certificadora subordinada.
- Emitir certificados X.509 firmados por una CA.
- Validar certificados X.509 emitidos por CAs generadas por la aplicación.
- Exponer las operaciones mediante una API REST.
- Restringir el acceso a la API a usuarios autorizados.
- Documentar dependencias externas y revisar vulnerabilidades.
- Preparar despliegue mediante Docker y Kubernetes.

## Estado actual

## Estado actual

- Implementada la lógica inicial de certificados:
    - Generación de una entidad certificadora raíz.
    - Generación de una entidad certificadora subordinada.
    - Emisión de certificados X.509 firmados por una CA.
    - Validación de certificados X.509 emitidos por CAs generadas por la aplicación.

## Estructura del proyecto

```text
crypto_service/
├── README.md
├── requirements.txt
├── src/
│   └── crypto_service/
│       ├── __init__.py
│       ├── certificate_authority.py
│       ├── helpers.py
│       ├── main.py
│       └── validation.py
└── tests/