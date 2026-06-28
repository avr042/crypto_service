# Análisis de seguridad de dependencias

Este documento describe el inventariado de dependencias y el análisis de vulnerabilidades realizado para el proyecto `crypto_service`.

## Objetivo

El objetivo de este análisis es identificar las dependencias externas utilizadas por la aplicación, generar un inventario de componentes software y comprobar si las dependencias declaradas presentan vulnerabilidades conocidas.

## Inventario de dependencias

Las dependencias Python del proyecto están declaradas en el archivo:

```text
requirements.txt
```

Además, se han generado SBOMs en formato CycloneDX para disponer de un inventario estructurado de los componentes software utilizados por la aplicación.

Los SBOMs generados se almacenan en:

```text
security-reports/sbom.json
security-reports/trivy-sbom.json
```

Donde:

```text
security-reports/sbom.json
```

corresponde al SBOM generado con `cyclonedx-py`.

```text
security-reports/trivy-sbom.json
```

corresponde al SBOM generado con Trivy.

## Herramientas utilizadas

Se han utilizado las siguientes herramientas:

```text
cyclonedx-py
```

Herramienta utilizada para generar un SBOM en formato CycloneDX a partir del entorno Python del proyecto.

```text
pip-audit
```

Herramienta utilizada para analizar las dependencias Python declaradas en `requirements.txt` y detectar vulnerabilidades conocidas.

```text
Trivy
```

Herramienta utilizada para generar un SBOM adicional y analizar SBOMs en busca de vulnerabilidades conocidas.


## Evidencias generadas

Las evidencias generadas se almacenan en la carpeta:

```text
security-reports/
```

Los archivos principales son:

```text
security-reports/sbom.json
security-reports/trivy-sbom.json
security-reports/pip-audit-report.json
security-reports/trivy-sbom-report.json
security-reports/trivy-sbom-analysis-report.json
```

## Resultados

El análisis realizado con `pip-audit` sobre `requirements.txt` no detectó vulnerabilidades conocidas en las dependencias Python declaradas.

El análisis realizado con Trivy sobre el SBOM en formato CycloneDX no detectó vulnerabilidades conocidas en los paquetes Python analizados.

El análisis realizado con Trivy sobre el SBOM generado por Trivy tampoco detectó vulnerabilidades conocidas.

## Acciones tomadas

No ha sido necesario actualizar dependencias como resultado de este análisis.

No se ha identificado ninguna dependencia vulnerable que requiera remediación inmediata.

## Consideraciones de seguridad

El resultado obtenido indica que no se han detectado vulnerabilidades conocidas en las dependencias analizadas en el momento de ejecución de las herramientas.
