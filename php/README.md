# SonarQube PHP test

Este directorio contiene `test.php` con ejemplos `GOOD` / `BAD` para probar el analizador PHP de SonarQube.

Requisitos:
- SonarQube corriendo (puedes usar el `docker/docker-compose.yml` incluido en el repo).
- Token de usuario para ejecutar el análisis (SonarQube token).

Arrancar SonarQube con Docker Compose (desde la raíz del repo):

```powershell
cd docker
docker-compose up -d
```

Ejecutar SonarScanner usando Docker (PowerShell):

```powershell
cd ..\php
docker run --rm -e SONAR_HOST_URL="http://localhost:9000" -e SONAR_LOGIN="<YOUR_TOKEN>" -v ${PWD}:/usr/src -w /usr/src sonarsource/sonar-scanner-cli -Dsonar.projectKey=sonarqube_php_test
```

O con `sonar-scanner` instalado localmente:

```powershell
cd php
sonar-scanner -Dsonar.login=<YOUR_TOKEN> -Dsonar.projectKey=sonarqube_php_test
```

Notas:
- Reemplaza `<YOUR_TOKEN>` por tu token de SonarQube.
- Ajusta `sonar-project.properties` si necesitas cambiar el `projectKey` o rutas.
