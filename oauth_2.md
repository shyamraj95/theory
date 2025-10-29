# System Design — Secure, Scalable OAuth 2.1 + OIDC Authentication & Authorization

**Purpose**: A production-grade design and implementation plan for an OAuth 2.1 + OpenID Connect based authentication and authorization stack using Keycloak (Authorization Server), Spring Boot 3.x (Resource Servers), Java 21, and Angular 20 frontend. The system supports internal (LDAP) and external (username+OTP) users, hybrid RSA-AES encrypted payloads, single-session enforcement, maker-checker user onboarding, and strong auditing and token revocation using Kafka + Caffeine caches.

---

## Table of contents
1. Overview & goals
2. Non-functional requirements
3. High-level architecture
4. Component responsibilities
5. Data model (entities)
6. Authentication & authorization flows
7. Encryption (hybrid RSA-AES) — payload design & key management
8. CAPTCHA generation & storage
9. Session, token lifecycle & revocation (Caffeine + Kafka)
10. Maker-Checker workflow & user provisioning
11. Role validation & external API checks
12. Resource server request validation (tabId/IP/JTI)
13. Caching and performance
14. Logging, auditing & monitoring
15. Deployment, scaling & infra considerations
16. Project structure & code generation guidance (per project)
17. Example configuration snippets
18. Security & production hardening checklist
19. Future roadmap (SSO/Kerberos)

---

# 1. Overview & goals
- Provide secure logins for internal and external users using OAuth2.1 + OIDC.
- Use Keycloak as the Authorization Server; Resource Servers are Spring Boot microservices that validate JWTs using JWKS.
- Frontend is Angular 20 using Authorization Code (PKCE) + DPoP for token binding.
- End-to-end request payload encryption: client encrypts request body using an AES key; AES key encrypted with server RSA public key (hybrid RSA-AES).
- Enforce single active session per user and block accounts after 3 failed attempts (per day).
- Maker-Checker workflow for user creation/approval and configurable conditional role rules.
- Token revocation and token-blocklist propagated via Kafka; resource servers cache blocked JTIs in Caffeine.

---

# 2. Non-functional requirements
- **Scalability**: microservices deployed in Kubernetes/OpenShift; stateless application servers for autoscaling.
- **Availability**: Keycloak in clustered mode (stateless fronted by load balancer); DB HA for user and audit stores.
- **Security**: TLS everywhere; RSA key rotation; short-lived access tokens and DPoP binding; refresh tokens revocable.
- **Performance**: Caffeine in-memory caches for read-heavy metadata (JTI, CAPTCHA); async Kafka for revocation events.
- **Auditability**: immutable audit table for login attempts, maker-checker actions, role changes, token block events.

---

# 3. High-level architecture
(Describe components; include a diagram in the final doc location)
- **Frontend (Angular 20)**: PKCE + DPoP client; encrypts payloads with per-request AES, sends AES key encrypted with Keycloak public RSA key (provided by an endpoint). Stores tabId in sessionStorage and passes to APIs via header.
- **Authorization Server (Keycloak)**: Realms for environments; LDAP identity provider for internal users; custom authenticator for CAPTCHA + OTP; REST endpoints for JWKS and public RSA key; event listeners to publish revocation/block events to Kafka.
- **Auth Service Adapter / Gateway** (optional): Lightweight Spring Boot service that handles hybrid-decryption of incoming login payloads before forwarding to Keycloak REST APIs (useful for enforcing handshake rules). Not strictly required if Keycloak has custom SPI.
- **Resource Servers (Spring Boot 3.x, Java 21)**: Validate JWT via JWKS; enforce token blocklist (Caffeine); decrypt responses using AES key (sent as part of request handshake) for APIs that must return encrypted bodies.
- **OTP/Notification Service**: Internal microservice to send SMS/Email OTPs. Use reliable delivery patterns and retry.
- **HRMS Connector**: Calls HRMS API when creating internal users to fetch PFID details.
- **Kafka**: Event bus for token revocation/block events, user-creation lifecycle events, and asynchronous audit processing.
- **Databases**: PostgreSQL (recommended) for users, roles, audit logs, maker-checker queues. Keycloak uses its own DB (or managed Keycloak offering).
- **Cache**: Caffeine deployed in each service instance for ephemeral caches (captcha, JTI blocklist, OTP attempts).

---

# 4. Component responsibilities

**Keycloak (Authorization Server)**
- OIDC provider with Authorization Code + PKCE + DPoP support (custom DPoP support via provider or using external plugin).
- LDAP Identity Provider for internal users.
- OTP federated authenticator (custom authenticator SPI) for external user second factor; integrate OTP service.
- Publish token issuance and revocation events to Kafka.
- Provide JWKS (public keys) and RSA public key endpoint for client-side hybrid-encryption.

**Spring Boot Resource Server(s)**
- Validate JWTs by verifying signature with JWKS and checking claims (aud, iss, exp, jti).
- Validate that token JTI is not blocked (Caffeine cache, fallback to DB or Kafka state store if needed).
- Enforce tabId and client IP checks from the cached JWT metadata.
- Decrypt request payloads (if needed) using AES key provided in handshake and encrypt responses with same AES key.
- Expose user management endpoints (maker/checker flows) and audit logging.

**Angular 20 Frontend**
- Implement PKCE + Authorization Code flow.
- Use DPoP to bind tokens to a public/private key pair created per-tab or per-session.
- Before sending POST/PUT/DELETE (non-multipart) requests: generate AES key, encrypt JSON payload, encrypt AES key with Keycloak RSA public key, include metadata headers (tabId, timestamp, nonce etc.).
- Handle first-time password reset flow for external users.
- Provide maker UI for user creation and checker UI for approvals.

---

# 5. Data model (key entities)
Provide sample ER definitions (simplified):

- **user** (id, username, display_name, email, mobile, pf_id, is_internal, status[pending/active/suspended], created_by, created_at, updated_at)
- **role** (id, name, description)
- **user_roles** (user_id, role_id, mapping_meta)
- **audit_log** (id, user_id, action, metadata(jsonb), created_at, source_ip)
- **login_attempt** (id, username, day_date, failed_count, last_failed_at)
- **pending_user** (id, payload_json, maker_id, created_at, circle_id, status)
- **raccp_mapping** (branch_id, cpc_id, circle_id, bpr_center_id, etc.)
- **token_blocklist** (jti, user_id, client_id, blocked_at, reason, expires_at)
- **captcha_store** (captcha_id, value_hash, created_at, expire_at) — ephemeral; prefer Caffeine cache with DB fallback if required

---

# 6. Authentication & Authorization flows

## 6.1 Login (internal via LDAP)
1. Angular opens PKCE auth request to Keycloak (Authorization Code flow). Include `acr_values` or login_hint to select internal flow.
2. Keycloak triggers LDAP authentication; before challenge, present CAPTCHA (custom authenticator) and check response.
3. On password success — check role validation rules (call external role validation API if required).
4. Create session: store JTI metadata in Keycloak DB and publish issuance event to Kafka with JTI, tabId (if provided), client IP.
5. Angular obtains tokens (access + id + refresh). Cache JTI metadata in Caffeine at resource servers when first API call happens.

## 6.2 Login (external via OTP)
1. User enters credentials through Angular; Keycloak custom authenticator validates password (DB), then triggers OTP service.
2. CAPTCHA required before initiating OTP.
3. OTP verified; if first-time login, redirect to password reset flow.
4. Tokens issued as above.

## 6.3 PKCE + DPoP + Encrypted payload
- Client completes PKCE with Keycloak. Client creates DPoP key pair and requests tokens; DPoP header included in token requests.
- For state-modifying requests (POST/PUT/DELETE): client creates a fresh AES-256-GCM key, encrypts payload JSON using AES-GCM (includes nonce/IV), then encrypts the AES key with the server RSA public key (Keycloak endpoint). Client sends headers: `X-Encrypted-Key` (base64), `X-Enc-IV`, `X-DPoP`, `X-Tab-Id`, `X-Nonce`, `X-Timestamp`.
- Resource server decrypts AES key using its RSA private key and decrypts payload; processes request and encrypts response body using same AES key.

---

# 7. Encryption (hybrid RSA-AES)

## Key choices
- **RSA**: RSA-4096 (or 3072 for performance) for encrypting AES keys. Keys stored in a secure KMS and mounted as secrets to services. Rotate keys quarterly or per policy.
- **AES**: AES-256-GCM for payload encryption; includes auth tag and resists tampering.
- **Nonce/IV**: use unique IV per encryption (12 bytes) and include IV header.

## Flow details
1. Client generates AES-256-GCM key K per-request.
2. Client encrypts JSON payload P => C = AES-GCM(K, IV, P).
3. Client encrypts K with server RSA public key R => E = RSA-OAEP(R, K).
4. Client sends headers: `X-Enc-Key: base64(E)`, `X-IV: base64(IV)`, `X-Tab-Id`, `X-TS`, `X-Nonce`, `Authorization: Bearer <access_token>` and body = C (base64 or binary with content-type `application/octet-stream` or `application/encrypted+json`).
5. Server decrypts E using RSA private key, recovers K, then AES-GCM-decrypts payload with IV.
6. For responses that must be encrypted, server uses K to produce AES-GCM ciphertext and returns it with `Content-Type: application/encrypted+json`.

**Replay protection**: require `X-Nonce` + `X-TS` and check within a small window (e.g., 30s). Cache used nonces per JTI in Caffeine (short expiry) to detect replay.

**Key distribution**: Keycloak exposes a public RSA encryption key endpoint (different from JWKS-signing keys) that Angular uses to encrypt AES keys. The RSA private key remains in Keycloak or in a decryption gateway service that has access to the private key stored in KMS. Optionally implement an encryption gateway that sits in front of Keycloak for decryption.

---

# 8. CAPTCHA generation & storage
- Implement custom CAPTCHA using Java2D / Java Graphics API (server-side) to render obfuscated text or image puzzles.
- Store the CAPTCHA answer hashed in Caffeine with TTL (e.g., 2 minutes) using `captcha_id` as key. Also store attempt count for that captcha.
- Expose CAPTCHA image endpoint: `/api/captcha/generate` returns `captcha_id` and image (base64 or blob).
- Validation: client returns `captcha_id` and `captcha_answer` (encrypted as payload or plain over TLS) during login/OTP initiation.

---

# 9. Session, token lifecycle & revocation

## Single session / one active session per user
- On successful login, Keycloak will check for existing active sessions for that user and ask the client whether to terminate previous session (UI prompt). If consent provided, Keycloak will revoke previous refresh tokens and publish revocation event.
- Alternatively, implement a `session_store` table and on login set `active_session_id` per user; previous sessions get invalidated by publishing their JTI as blocked.

## Failed attempts & blocking
- On failed login, increment `login_attempt` entry keyed by username and `day_date`. On 3 failed attempts, mark the account as `blocked` in `user` table; log audit row and send admin notification. Admin UI can unblock; otherwise schedule auto-unblock at midnight or on next day roll.

## Token revocation propagation
- Keycloak (or auth-adapter) publishes `token_revoked` events to Kafka with JTI and expiration time.
- Resource servers subscribe to revocation topic and insert JTI into local Caffeine blocklist with TTL equal to token remaining lifetime.
- On logout, client calls Keycloak revocation endpoint; Keycloak publishes revocation event.
- Resource server may also locally block tokens on suspicious activity and publish to Kafka.

---

# 10. Maker-Checker workflow & user provisioning

**Maker flow**
- Maker creates a `pending_user` record via UI or API; validations: branch, role rules (conditional) — if internal, fetch HRMS details using PF ID and populate profile.
- Temporary password generated and stored hashed; send temp password via OTP service to user contact.
- Maker assigns roles and RACPC mappings.

**Checker flow**
- Checker UI lists pending users filtered by circle; checker approves/rejects. Approve triggers final creation in the `user` table and calls Keycloak Admin API to create a Keycloak user and attach required realm roles / client roles and attributes.
- On approve, publish event to Kafka (`user_created`) with user metadata for downstream systems.

**Bulk upload**
- Excel upload service validates data rows, creates pending_user records, and sends notifications.

**Conditional roles**
- Rules engine: configurable rules stored in DB; evaluated by maker UI and re-checked at checker time. Example rule for CIT: `branch_id == cpc.branch_id AND (esg in [3,4]) AND (eg == 'J')`.

---

# 11. Role validation & external API checks
- When certain internal roles are assigned (COD, CPC Head), call external Role Validation API synchronously during approval. If external API returns negative, mark user `requires_manual_review` and halt approval.
- Cache validation responses (Caffeine) for short TTL to reduce load.

---

# 12. Resource server: request validation (tabId/IP/JTI)
- On token issuance, Keycloak includes custom claim `tab_id` (if client provides `tabId` during auth exchange) and publishes JTI metadata to an endpoint.
- Resource servers cache JWT metadata keyed by `jti` in Caffeine: `{tabId, client_ip, token_status:'active'}` with TTL = token lifetime.
- For each request:
  - Verify JWT signature via JWKS and check `exp`.
  - Lookup `jti` in local cache. If missing, fetch from Keycloak introspect endpoint or allow-but-populate cache.
  - Compare `tabId` and client IP; if mismatch, respond 401 and optionally publish block event.
  - If JTI is blocked or expired, reject.

**Note**: client IP detection should consider proxies (use standard forwarded headers) and must be consistent between issuance and resource server checks.

---

# 13. Caching & performance
- Use **Caffeine** for ephemeral caches in each service instance:
  - CAPTCHA store (short TTL)
  - JTI blocklist and JTI metadata (TTL = token duration)
  - Nonces for replay protection (TTL = 60s)
  - Role validation cache (short TTL)
- Use Redis only if cross-instance caching with strong consistency is required; otherwise use Kafka events and local caches for eventual consistency.
- Database indexing: `user(username)`, `login_attempt(username, day_date)`, `pending_user(status, circle_id)`, `token_blocklist(jti)`.

---

# 14. Logging, auditing & monitoring
- **Audit**: immutable audit_log with JSON metadata; log maker/checker actions, token revocations, login attempts, role assignment changes.
- **Access logs**: structured logs for requests, include fields: jti, user_id, client_id, tabId, ip, endpoint, latency, response_code.
- **Monitoring**: Prometheus metrics from Spring Boot Actuator and Keycloak metrics; expose cache hit/miss, Kafka lag, DB pool usage.
- **Tracing**: OpenTelemetry for distributed tracing across frontend gateway, Keycloak, resource servers, and Kafka consumers.

---

# 15. Deployment & scaling
- Containerize each microservice; use Kubernetes/OpenShift.
- Keycloak: run in HA with DB cluster and sticky sessions disabled (Keycloak clustering or operator-managed install).
- Use an ingress layer / API gateway to terminate TLS and provide rate-limiting and WAF.
- Use rolling deployments and readiness/liveness probes.

Storage & secrets
- Use KMS (HashiCorp Vault / cloud KMS) for RSA private keys and DB credentials.
- Mount keys via secure secrets provider (do not bake keys in images).

---

# 16. Project structure & code generation guidance

## Projects to generate (suggested names)
1. `auth-gateway` (optional): decrypts hybrid payloads, forwards to Keycloak; Spring Boot. — *code optional*
2. `keycloak-config` (infrastructure repo): realm definitions, client configs, authentication flow definitions, custom SPI jars (CAPTCHA/OTP plugin) — artifacts only.
3. `user-service` (maker-checker, HRMS connector): Spring Boot 3.x, Java 21, Spring Data JPA.
4. `resource-api-<domain>`: resource servers that validate JWTs and enforce tabId/IP checks; Spring Boot 3.x.
5. `otp-service`: microservice for OTP generation & delivery.
6. `notification-service`: email/SMS templating.
7. `frontend-app` (Angular 20): PKCE + DPoP client and UI for login, maker/checker, admin console.

### Skeleton: Spring Boot microservice (resource server)
- `src/main/java/.../Application.java` (Spring Boot 3.5+)
- `application.yml` with `spring.security.oauth2.resourceserver.jwt.jwk-set-uri` pointing to Keycloak JWKS.
- Use `spring-boot-starter-security`, `spring-boot-starter-web`, `spring-boot-starter-data-jpa`.
- Add `caffeine` dependency and configure beans for caches.
- Implement `OncePerRequestFilter` to decrypt incoming payloads and validate tabId/ip.

### Skeleton: Angular 20 app
- `@auth0/angular-jwt` (or custom) for token handling; implement PKCE flow using `oauth2-client-js` or custom library.
- Implement DPoP creation per-tab and store private key in `sessionStorage` keyed by `tabId`.
- Provide an encryption module to generate AES keys and perform RSA encryption of the AES key using Keycloak public key fetched from `/protocol/openid-connect/encrypt-key` endpoint.

---

# 17. Example configuration snippets

## Spring Boot (resource server) application.yml (excerpt)
```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: https://keycloak.example.com/auth/realms/myrealm/protocol/openid-connect/certs
server:
  port: 8080
caffeine:
  spec: maximumSize=10000,expireAfterWrite=1h
```

## Caffeine cache bean (Spring Java)
```java
@Bean
public Cache<String, JwtMeta> jtiCache() {
  return Caffeine.newBuilder()
    .expireAfterWrite(Duration.ofMinutes(60))
    .maximumSize(10000)
    .build();
}
```

## Example filter pseudo-code for decrypt-and-validate
```java
public class EncryptedPayloadFilter extends OncePerRequestFilter {
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) {
    String encKey = req.getHeader("X-Enc-Key");
    String iv = req.getHeader("X-IV");
    if (encKey != null) {
      byte[] encryptedAesKey = Base64.getDecoder().decode(encKey);
      byte[] aesKey = rsaDecrypt(encryptedAesKey); // from KMS or local private key
      byte[] cipherBody = req.getInputStream().readAllBytes();
      byte[] plain = aesGcmDecrypt(aesKey, Base64.getDecoder().decode(iv), cipherBody);
      HttpServletRequest wrapped = new CachedBodyHttpServletRequest(req, plain);
      chain.doFilter(wrapped, res);
      // on response: capture output and encrypt with aesKey
    } else {
      chain.doFilter(req, res);
    }
  }
}
```

---

# 18. Security & production hardening checklist
- TLS 1.2+ and HSTS; strong ciphers only.
- KMS-managed RSA private keys; rotate keys regularly.
- Short-lived access tokens (e.g., 5–15 minutes), refresh tokens revocable.
- Store only hashed passwords (bcrypt/argon2) for external user DB.
- Sanitize all inputs; use prepared statements and strong ORM checks.
- Rate-limit login endpoints and CAPTCHA generation.
- Protect against replay via nonce + timestamp and track nonces in Caffeine.
- CSP, X-Frame-Options, secure cookies, SameSite=strict for cookies.
- Pen-test / code-scan and regular dependency scanning.

---

# 19. Future roadmap
- Integrate Kerberos / Windows SSO for internal users to allow seamless SSO.
- Consider replacing Keycloak with a managed OIDC provider if operational overhead is high.
- Add device posture checks (MFA device health) and adaptive authentication.

---

# 20. Deliverables & next steps
1. Realm definition JSON for Keycloak (clients, roles, authentication flows, mappers).
2. Custom Keycloak SPI JARs for CAPTCHA and OTP (server-side authenticators).
3. Seed Spring Boot microservice templates (user-service, resource services, otp service) with caching/filters.
4. Angular 20 skeleton implementing PKCE + DPoP and hybrid encryption module.
5. CI/CD pipeline templates (Dockerfile + Kubernetes manifests + Helm charts).

---

## Appendix: Helpful implementation notes
- Put heavy cryptography operations in native libraries or well-tested Java libraries; avoid implementing crypto primitives yourself.
- Avoid sending RSA private keys to any frontend; only public keys are exposed to clients.
- Use AES-GCM; avoid AES-CBC unless authenticated encryption is layered.
- Keep token revocation synchronous only when necessary; prefer Kafka events for eventual consistency.


---

*Document generated: system-design / security & application architecture for OAuth2.1 + OIDC with Keycloak, Spring Boot 3.x, Java 21 and Angular 20.*

