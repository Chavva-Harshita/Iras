# IRAS backend (Spring Boot)

Maven API for IRAS. The Next.js storefront stays at the repository root (`app/`).

## Requirements

- **JDK:** the project compiles for **Java 21**. A JDK 17+ can run the toolchain; **JDK 21 is preferred**.
- **Maven:** use the Maven Wrapper (`mvnw` / `mvnw.cmd`). A global Maven install is not required.
- **PostgreSQL:** not required to *start* this foundation. Flyway is off until Prompt 4. Set `FLYWAY_ENABLED=true` only after migrations exist and the database is reachable.

## Environment variables

| Variable | Purpose | Development default |
|---|---|---|
| `DATABASE_URL` | JDBC URL | `jdbc:postgresql://localhost:5432/iras` |
| `DATABASE_USERNAME` | Database user | `iras` |
| `DATABASE_PASSWORD` | Database password | empty (set this locally; do not commit secrets) |
| `SERVER_PORT` | HTTP port | `8080` |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins | `http://localhost:3000,http://127.0.0.1:3000` |
| `FLYWAY_ENABLED` | Run Flyway on startup | `false` |

On Windows (PowerShell):

```powershell
$env:JAVA_HOME = "C:\path\to\jdk-21"
$env:DATABASE_PASSWORD = "your-local-password"
```

## Start

From `backend/`:

```powershell
.\mvnw.cmd spring-boot:run
```

Health check:

```
GET http://localhost:8080/api/health
```

Expected:

```json
{"status":"UP","service":"IRAS backend"}
```

Actuator health is also available at `/actuator/health`.
