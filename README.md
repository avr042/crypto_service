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

* Implementada la lógica principal de certificados:

  * Generación de una entidad certificadora raíz.
  * Generación de entidades certificadoras subordinadas.
  * Emisión de certificados X.509 firmados por una CA.
  * Validación de cadenas de certificados X.509 emitidas por CAs generadas por la aplicación.

* Implementada persistencia local del material criptográfico:

  * Almacenamiento de CAs en `storage/cas/`.
  * Almacenamiento de certificados emitidos en `storage/certificates/`.
  * Almacenamiento de claves públicas de entidades finales simuladas en `storage/entities/`.
  * Uso de índices JSON para localizar CAs y certificados generados.

* Implementada API REST con FastAPI:

  * `POST /crypto/ca`: creación de Root CA.
  * `GET /crypto/ca`: listado de CAs disponibles.
  * `POST /crypto/subca`: creación de SubCA.
  * `POST /crypto/issue`: emisión de certificados para entidades conocidas.
  * `POST /crypto/validate`: validación de certificados emitidos.
  * `GET /crypto/entities`: listado de entidades finales conocidas.
  * `GET /crypto/certificates`: listado de certificados emitidos.

* Implementado control de acceso a la API:

  * Endpoint público `POST /auth/login` para autenticación de usuarios.
  * Autenticación mediante tokens Bearer con JWT.
  * Usuarios de demostración hardcodeados para la prueba técnica.

* Realizado inventariado y análisis de seguridad de dependencias:

  * Generación de SBOMs en formato CycloneDX.
  * Análisis de `requirements.txt` mediante `pip-audit`.
  * Análisis de SBOMs mediante Trivy.
  * Documentación del proceso y los resultados en `SECURITY_DEPENDENCIES.md`.
  * No se ha realizado ninguna acción adicional, ya que no se han detectado vulnerabilidades conocidas en las dependencias analizadas.


* Añadidas funcionalidades auxiliares para facilitar la demostración:

  * Creación de un entorno PKI de prueba mediante `demo_environment.py`.
  * Generación de Root CA, varias SubCAs y claves de entidades finales simuladas.
  * Emisión y consulta de certificados mediante identificadores internos en la API.

* Implementada contenerización básica con Docker



```text
crypto_service/
├── .dockerignore
├── Dockerfile
├── README.md
├── SECURITY_DEPENDENCIES.md
├── requirements.txt
├── security-reports/
│   ├── sbom.json
│   ├── trivy-sbom.json
│   ├── pip-audit-report.json
│   ├── trivy-sbom-report.json
│   └── trivy-sbom-analysis-report.json
├── storage/
│   ├── cas/
│   │   ├── index.json
│   │   └── <ca-directory>/
│   │       └── certificate.pem
│   ├── certificates/
│   │   ├── index.json
│   │   └── <certificate-directory>/
│   │       └── certificate.pem
│   └── entities/
│       └── <entity-common-name>/
│           └── public_key.pem
└── src/
    └── crypto_service/
        ├── __init__.py
        ├── api.py
        ├── auth.py
        ├── certificate_authority.py
        ├── demo_environment.py
        ├── helpers.py
        ├── main.py
        └── validation.py
```



## Ejecución

Crear el entorno de demostración:

```powershell
$env:PYTHONPATH = "src"
python -m crypto_service.main
```

Levantar la API REST:

```powershell
$env:PYTHONPATH = "src"
python -m uvicorn crypto_service.api:app --reload
```

La documentación interactiva de la API estará disponible en:

```text
http://localhost:8000/docs
```

## Ejecución con Docker

Construir la imagen:

```powershell
docker build -t crypto-service:0.1.0 .
```

Ejecutar el contenedor:

```powershell
docker run --rm -p 8000:8000 -e JWT_SECRET_KEY="demo-docker-secret" crypto-service:0.1.0
```

La API quedará disponible en:

```text
http://localhost:8000/docs
```

Para ejecutar la aplicación utilizando la carpeta local `storage/` como almacenamiento persistente:

```powershell
docker run --rm -p 8000:8000 -e JWT_SECRET_KEY="demo-docker-secret" -v ${PWD}\storage:/app/storage crypto-service:0.1.0
```

La variable de entorno `JWT_SECRET_KEY` se utiliza para configurar la clave de firma de los tokens JWT sin incluir secretos dentro de la imagen Docker.
