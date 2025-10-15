<p align="center">
  <img src="https://raw.githubusercontent.com/Gua-ra/gua-branding/refs/heads/main/logos/gua-logo-transparent.png" alt="Gua Logo" width="200"/>
</p>


# Gua Identity Service

The **Gua Identity Service** is a Spring Boot–based microservice that handles **user identity and authentication flows** for the Gua messaging platform.  
It is responsible for phone-number–based login, OTP (one-time password) management, and future identity integrations (such as gov.br SSO and PIX identity linking).

---

## ✨ Features (planned / implemented)

- 📱 **Phone number login**: request OTP → verify OTP → issue Matrix-compatible access.
- 🔐 **OTP storage with expiry** (Redis-backed).
- 🗄️ **Persistent user identities** (PostgreSQL, with Flyway for schema migrations).
- ⚡ **REST API endpoints** for clients (Element-X fork → Gua client).
- 🛂 **Minimal OpenID Connect provider** for Matrix Authentication Service (authorization code + userinfo).
- 🚀 **Extensible**

---

## 🛠️ Tech Stack

- **Java 21** (LTS, recommended for production)
- **Spring Boot 3.5.x**
- **Gradle (Groovy DSL)**
- **Spring Web** (REST controllers)
- **Spring Data JDBC** (DB access)
- **Flyway** (DB migrations)
- **Spring Data Redis** (OTP store)
- **Spring Boot Validation** (input validation)

Databases / Infra:
- **PostgreSQL** → main user identity storage
- **Redis** → short-lived OTP tokens
- **Docker Compose** -> infra

---
## 🚧 Local development stack

Spin up Redis, Postgres, and a disposable Synapse homeserver with a single command:

```bash
# run and export environment variables into the current shell
source scripts/start-dev-test-stack.sh
```


Running the script normally (`bash scripts/start-dev-test-stack.sh`) will still launch the containers; it also writes the computed environment variables to `.env.identity-service` so you can load them manually with `source .env.identity-service` or copy them into IntelliJ.

What the script does:

1. Starts all dependencies using `docker-compose.test.yml`.
2. Waits for Synapse to become healthy.
3. Creates (or reuses) an admin Matrix user and captures its access token.
4. Generates a directory pepper (stored at `docker/.identity-pepper`) for consistent hashing.
5. Exports all required environment variables for the identity service.

Once the script has been sourced you can run the application with `./gradlew bootRun` or from IntelliJ without additional environment setup. To tear everything down:

```bash
docker compose -f docker-compose.test.yml down
```

---

## 🧪 Tests

```bash
./gradlew test
```

---

## 🔐 OpenID Connect bridge

The service doubles as a lightweight OIDC-compatible identity provider so that [Matrix Authentication Service (MAS)](https://github.com/element-hq/matrix-authentication-service/) can delegate user login to phone-based OTP flows.

### Endpoints

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery metadata describing issuer, authorization, token, userinfo, and JWKS endpoints |
| `GET /.well-known/jwks.json` | Publishes the HMAC signing key used for ID/access tokens |
| `GET /oauth2/authorize` | Accepts `client_id`, `redirect_uri`, `response_type=code`, `scope`, `phone_number`, `otp_code`, optional `display_name`/`state`; issues an authorization code after validating the OTP |
| `POST /oauth2/token` | Exchanges an authorization code for a signed access token (and ID token) |
| `GET /userinfo` | Returns the authenticated subject (`sub`), `phone_number`, and optional `name` |

Tokens are signed with the secret supplied via `OIDC_JWT_SIGNING_SECRET` (HMAC-SHA256). The external issuer URL is derived from `IDENTITY_BASE_URL`, so ensure it points to the publicly reachable base path (e.g. `https://identity.example.com`).

Authorization codes are short-lived (default 5 minutes) and stored in Redis to maintain statelessness across multiple instances.

---

## 🛡️ Rate limiting

Every public endpoint is protected by a Resilience4j-based rate limiter so the service can run safely without an upstream proxy or WAF. The defaults (tuned for local development) are defined in `application.yml` under `identity.rate-limits`. You can override any value via environment variables; for example:

| Endpoint | Default limit | Refresh window | Env override |
| --- | --- | --- | --- |
| `POST /otp/send` | 5 requests | 1 minute | `IDENTITY_RATE_LIMIT_OTP_SEND_LIMIT` |
| `POST /security/pin/reset` | 3 requests | 1 hour | `IDENTITY_RATE_LIMIT_SECURITY_PIN_RESET_LIMIT` |
| `POST /directory/lookup` | 30 requests | 5 minutes | `IDENTITY_RATE_LIMIT_DIRECTORY_LOOKUP_LIMIT` |

If you need to disable the limiter (e.g., for load testing) set `IDENTITY_RATE_LIMITS_ENABLED=false`. Otherwise, clients receive HTTP `429` responses with a JSON body (`{"message":"Rate limit exceeded"}`) and a `Retry-After` header indicating when they may retry.

---
## 🚀 Deployment

### Build the container image

```bash
docker build -t gua/identity-service:latest .
```

### Compose file

An example `docker-compose.identity.yml` is included. Provide environment values (either via a `.env` file or directly in your orchestration system) for:

- `SPRING_DATASOURCE_*` – JDBC details for Postgres
- `SPRING_DATA_REDIS_*` – Redis host/port
- `IDENTITY_MATRIX_*` – Synapse endpoints and admin token
- `IDENTITY_DIRECTORY_PEPPER` – server-side secret used to hash phone digests
- `OIDC_JWT_SIGNING_SECRET` – HMAC secret used to sign OIDC access and ID tokens

Then run:

```bash
docker compose -f docker-compose.identity.yml up -d --build
```

The container exposes port `8080` by default and relies on the surrounding services (Postgres/Redis/Synapse) defined in the compose file. Adjust or remove the bundled Postgres/Redis services if you point at managed instances instead.

---
