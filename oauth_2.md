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





////////////////////////////////////





Excellent 👏 — this is where we make your **Keycloak ↔ External Role Validation** integration fully production-ready.

Below is a **complete implementation blueprint** for your **Custom Keycloak Authenticator SPI** project, including:
✅ Project structure
✅ Maven configuration
✅ Java classes
✅ Flow XML configuration (to register in Keycloak)
✅ Step-by-step Keycloak admin setup

---

## 🏗️ 1. Project Structure — `keycloak-external-role-validator`

```
keycloak-external-role-validator/
├── pom.xml
├── src/
│   ├── main/
│   │   ├── java/com/spleenior/keycloak/rolevalidator/
│   │   │   ├── ExternalRoleValidatorFactory.java
│   │   │   ├── ExternalRoleValidatorAuthenticator.java
│   │   │   ├── ExternalRoleApiClient.java
│   │   │   ├── RoleValidationResponse.java
│   │   │   └── CaffeineCacheProvider.java
│   │   └── resources/
│   │       ├── META-INF/services/org.keycloak.authentication.AuthenticatorFactory
│   │       ├── META-INF/services/org.keycloak.authentication.Authenticator
│   │       └── external-role-validator-flow.xml
│   └── test/java/... (optional)
```

---

## ⚙️ 2. Maven Dependencies

Use a Keycloak version that matches your server (e.g., 24.x or 25.x).

```xml
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.spleenior.keycloak</groupId>
  <artifactId>external-role-validator</artifactId>
  <version>1.0.0</version>
  <packaging>jar</packaging>

  <dependencies>
    <dependency>
      <groupId>org.keycloak</groupId>
      <artifactId>keycloak-server-spi</artifactId>
      <version>${keycloak.version}</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.keycloak</groupId>
      <artifactId>keycloak-server-spi-private</artifactId>
      <version>${keycloak.version}</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.12</version>
    </dependency>
    <dependency>
      <groupId>com.github.ben-manes.caffeine</groupId>
      <artifactId>caffeine</artifactId>
      <version>3.1.8</version>
    </dependency>
    <dependency>
      <groupId>org.apache.httpcomponents.client5</groupId>
      <artifactId>httpclient5</artifactId>
      <version>5.3</version>
    </dependency>
  </dependencies>
</project>
```

---

## 🧠 3. Core Java Classes

### (a) `ExternalRoleValidatorAuthenticator.java`

```java
package com.spleenior.keycloak.rolevalidator;

import org.keycloak.authentication.*;
import org.keycloak.models.*;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.validation.Validation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExternalRoleValidatorAuthenticator implements Authenticator {

    private static final Logger log = LoggerFactory.getLogger(ExternalRoleValidatorAuthenticator.class);
    private final ExternalRoleApiClient apiClient = new ExternalRoleApiClient();
    private final CaffeineCacheProvider cache = CaffeineCacheProvider.getInstance();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        String username = user.getUsername();
        String primaryRole = user.getFirstAttribute("primaryRole");

        if (Validation.isBlank(primaryRole)) {
            log.warn("User {} does not have a primaryRole attribute", username);
            context.success();
            return;
        }

        // Check cache first
        String cacheKey = username + "_" + primaryRole;
        Boolean cachedValid = cache.get(cacheKey);
        if (cachedValid != null && cachedValid) {
            log.info("Role validation (cached) passed for {}", username);
            context.success();
            return;
        }

        // Call external API
        RoleValidationResponse result = apiClient.validateRole(username, primaryRole);
        if (result != null && result.valid()) {
            log.info("External role validation succeeded for {}", username);
            user.setSingleAttribute("circleId", result.circleId());
            user.setSingleAttribute("branchId", result.branchId());
            user.setSingleAttribute("raccpId", result.raccpId());
            cache.put(cacheKey, true);
            context.success();
        } else {
            log.error("Role validation failed for user {}", username);
            context.cancelLogin();
            context.failure(AuthenticationFlowError.INVALID_USER,
                context.form().setError("Role verification failed. Contact admin.").createErrorPage());
        }
    }

    @Override public void action(AuthenticationFlowContext context) {}
    @Override public boolean requiresUser() { return true; }
    @Override public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) { return true; }
    @Override public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}
    @Override public void close() {}
}
```

---

### (b) `ExternalRoleValidatorFactory.java`

```java
package com.spleenior.keycloak.rolevalidator;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

public class ExternalRoleValidatorFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "external-role-validator";

    @Override public String getId() { return PROVIDER_ID; }
    @Override public String getDisplayType() { return "External Role Validator"; }
    @Override public String getHelpText() { return "Validates internal user roles (COD, CPC Head) via external API"; }
    @Override public Authenticator create(KeycloakSession session) { return new ExternalRoleValidatorAuthenticator(); }

    @Override public boolean isConfigurable() { return false; }
    @Override public List<ProviderConfigProperty> getConfigProperties() { return List.of(); }
    @Override public void init(org.keycloak.Config.Scope config) {}
    @Override public void postInit(org.keycloak.models.KeycloakSessionFactory factory) {}
    @Override public void close() {}
}
```

---

### (c) `ExternalRoleApiClient.java`

```java
package com.spleenior.keycloak.rolevalidator;

import org.apache.hc.client5.http.fluent.Request;
import org.apache.hc.core5.http.HttpStatus;
import org.json.JSONObject;

public class ExternalRoleApiClient {

    private static final String API_URL = System.getProperty("external.role.api", "https://internal.api/validateRole");

    public RoleValidationResponse validateRole(String username, String role) {
        try {
            JSONObject req = new JSONObject();
            req.put("username", username);
            req.put("role", role);

            String jsonResponse = Request.post(API_URL)
                .addHeader("Authorization", "Bearer " + System.getenv("ROLE_API_TOKEN"))
                .bodyString(req.toString(), null)
                .execute()
                .returnContent().asString();

            JSONObject res = new JSONObject(jsonResponse);
            if (res.optBoolean("valid", false)) {
                return new RoleValidationResponse(
                        true,
                        res.optString("circleId", null),
                        res.optString("branchId", null),
                        res.optString("raccpId", null)
                );
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new RoleValidationResponse(false, null, null, null);
    }
}
```

---

### (d) `RoleValidationResponse.java`

```java
package com.spleenior.keycloak.rolevalidator;

public record RoleValidationResponse(boolean valid, String circleId, String branchId, String raccpId) {}
```

---

### (e) `CaffeineCacheProvider.java`

```java
package com.spleenior.keycloak.rolevalidator;

import com.github.benmanes.caffeine.cache.*;

import java.util.concurrent.TimeUnit;

public class CaffeineCacheProvider {

    private static final Cache<String, Boolean> cache = Caffeine.newBuilder()
            .expireAfterWrite(15, TimeUnit.MINUTES)
            .maximumSize(10000)
            .build();

    private static final CaffeineCacheProvider INSTANCE = new CaffeineCacheProvider();
    private CaffeineCacheProvider() {}
    public static CaffeineCacheProvider getInstance() { return INSTANCE; }

    public Boolean get(String key) { return cache.getIfPresent(key); }
    public void put(String key, Boolean value) { cache.put(key, value); }
}
```

---

## 🧩 4. Authentication Flow XML (`external-role-validator-flow.xml`)

```xml
<authenticationFlow alias="browser-with-role-validation" description="Browser flow with external role validation" providerId="basic-flow" topLevel="true" builtIn="false">
    <authenticationExecutions>
        <!-- 1. Username and Password -->
        <execution authenticator="auth-username-password-form" requirement="REQUIRED"/>

        <!-- 2. External Role Validator -->
        <execution authenticator="external-role-validator" requirement="REQUIRED"/>

        <!-- 3. OTP / OTP Form if applicable -->
        <execution authenticator="auth-otp-form" requirement="CONDITIONAL"/>
    </authenticationExecutions>
</authenticationFlow>
```

---

## 🧰 5. Registering and Enabling the Flow in Keycloak

### Step 1 — Deploy JAR

Copy your compiled JAR:

```bash
cp target/external-role-validator-1.0.0.jar /opt/keycloak/providers/
```

### Step 2 — Restart Keycloak

```bash
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start --spi-theme-static-max-age=-1
```

### Step 3 — Configure Flow

In **Admin Console**:

1. Go to **Authentication → Flows**
2. Create a new flow → *Import from XML* (select `external-role-validator-flow.xml`)
3. Set as **Browser Flow** for your realm.

---

## 🧾 6. JWT Enrichment

Add a **Protocol Mapper** in your client (OIDC Client):

* Mapper type: “User Attribute”
* Attribute name: `circleId`, `branchId`, `raccpId`
* Token Claim Name: same as attribute
* Include in Access Token: ✅ checked
* Include in ID Token: ✅ checked

So your JWT will include:

```json
{
  "preferred_username": "pf12345",
  "roles": ["COD"],
  "circleId": "C001",
  "branchId": "B123",
  "raccpId": "RACPC99"
}
```

---

## 🧠 7. Production Tips

| Concern            | Best Practice                                                  |
| ------------------ | -------------------------------------------------------------- |
| External API auth  | Use mTLS or signed JWT system token                            |
| Timeout            | ≤3 seconds                                                     |
| Fallback           | Deny login if API unreachable                                  |
| Cache invalidation | Auto-expire after 15 mins                                      |
| Secure config      | Set `external.role.api` and token in Keycloak startup env vars |

---

////////////////////////////////////



Perfect follow-up — this is a **critical piece** in your architecture, because you’re combining **Keycloak’s local role management** with **external validation via an authoritative third-party API** (for example, a Core Banking, HRMS, or Role Registry API).

Let’s break this down into a *secure, production-grade* design pattern:

---

## 🧩 Objective

When a user (say, **CPC_HEAD** or **COD**) logs in:

* Keycloak must **not blindly trust** the stored roles.
* Instead, it must **validate** those roles against a **third-party API** (the source of truth).
* If the role is still valid → continue login and issue JWT with that role.
* If invalid (e.g. user transferred, revoked) → deny login or remove role claim.

---

## ⚙️ Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│                            Keycloak                             │
│  ┌──────────────────────────┐   ┌────────────────────────────┐  │
│  │ Custom Authenticator SPI │──▶│ External Role Validation   │  │
│  │  (Execution in flow)     │   │  Service API (3rd Party)   │  │
│  └──────────────────────────┘   └────────────────────────────┘  │
│         ▲             │                                        │
│         │             ▼                                        │
│     LDAP Bind     Token Issuance                               │
└────────────────────────────────────────────────────────────────┘
```

### Key Components:

1. **Custom Authenticator SPI** → runs during authentication flow.
2. **External API** → REST endpoint that validates user role and mapping.
3. **Role Sync/Override Logic** → updates user attributes/roles dynamically.

---

## 🧠 Step-by-Step Flow (CPC Head / COD Login)

### 1️⃣ User enters credentials

* Internal user authenticates via **LDAP bind** (or external via OTP, depending on user type).
* If credentials are valid, Keycloak proceeds to **Custom Authenticator**.

---

### 2️⃣ Custom Authenticator SPI runs

* This is a **Java class** implementing `Authenticator` interface in Keycloak SPI.
* It’s executed as a step in your **authentication flow** (after LDAP or OTP validation, before issuing tokens).

**Key Steps inside SPI:**

```java
public void authenticate(AuthenticationFlowContext context) {
    String username = context.getUser().getUsername();
    String role = context.getUser().getFirstAttribute("primaryRole"); // e.g. COD or CPC_HEAD
    String apiUrl = "https://thirdparty-system/api/validateRole";

    HttpResponse<String> response = Unirest.post(apiUrl)
        .header("Authorization", "Bearer " + SYSTEM_TOKEN)
        .body("{\"username\":\"" + username + "\",\"role\":\"" + role + "\"}")
        .asString();

    if (response.getStatus() == 200 && response.getBody().contains("\"valid\":true")) {
        // ✅ Role verified
        context.success();
    } else {
        // ❌ Invalid or expired role
        context.cancelLogin();
        context.failure(AuthenticationFlowError.INVALID_USER,
            context.form().setError("Your current role is not authorized for login.").createErrorPage());
    }
}
```

---

### 3️⃣ External Role Validation API

* The **third-party API** receives:

  ```json
  {
    "username": "pf12345",
    "role": "COD"
  }
  ```
* It checks in its authoritative source (e.g. HRMS / Circle Mapping DB) whether:

  * User exists in that role,
  * Branch/Circle assignment still valid,
  * Role active (not transferred/disabled).
* Returns:

  ```json
  {
    "valid": true,
    "circleId": "C001",
    "branchId": "B123",
    "raccpId": "RACPC99",
    "role": "COD"
  }
  ```

---

### 4️⃣ Keycloak updates user data dynamically

If API confirms validity:

* Update Keycloak **user attributes** and **roles** for accurate JWT content:

  ```java
  user.setSingleAttribute("circleId", response.circleId());
  user.setSingleAttribute("branchId", response.branchId());
  user.setSingleAttribute("raccpId", response.raccpId());
  user.setSingleAttribute("validatedBy", "external-role-api");
  ```

* Assign the verified role dynamically:

  ```java
  RoleModel roleModel = realm.getRole(role);
  if (!user.hasRole(roleModel)) user.grantRole(roleModel);
  ```

If invalid → authentication fails (user never receives JWT).

---

### 5️⃣ JWT Issuance

* After success, Keycloak issues token with:

  * Standard claims: `sub`, `preferred_username`
  * Role claim: `roles: ["COD"]`
  * Location claims: from user attributes (`circleId`, `raccpId`)
* Resource servers can trust this JWT because the **role was freshly verified** at login time.

---

## 🔄 Optional Optimization — Cached Role Validation

If you want to reduce load on the external API:

* Add **short-term caching** (e.g. 15 mins) using:

  * Redis, or
  * Java `Caffeine` inside Keycloak SPI.

Example:

```java
Cache<String, Boolean> cache = Caffeine.newBuilder()
    .expireAfterWrite(15, TimeUnit.MINUTES)
    .maximumSize(10000)
    .build();

Boolean cachedResult = cache.getIfPresent(username + "_" + role);
if (cachedResult == null) {
    // call API
    cache.put(username + "_" + role, apiResponse.isValid());
}
```

This balances **performance** and **security**.

---

## 🔐 Security Considerations

| Concern                         | Mitigation                                    |
| ------------------------------- | --------------------------------------------- |
| **External API unavailability** | Fallback: deny login or use cached validation |
| **API spoofing / MITM**         | Mutual TLS or signed JWT (Keycloak → API)     |
| **Sensitive data leak**         | Use POST + HTTPS only                         |
| **Timeout impact**              | Set short connect/read timeouts (2–3s)        |
| **Abuse**                       | Rate-limit requests from Keycloak node        |

---

## 📦 Deployment Integration

| Component                  | Type         | Location                                     |
| -------------------------- | ------------ | -------------------------------------------- |
| Keycloak Authenticator SPI | Custom JAR   | `/opt/keycloak/providers/`                   |
| Config                     | JSON/YAML    | `/opt/keycloak/conf/external-role-check.yml` |
| Third-Party Role API       | Microservice | internal network (behind API Gateway)        |

---

## ✅ Summary

| Feature                    | Implementation                        |
| -------------------------- | ------------------------------------- |
| Verify role (COD/CPC_HEAD) | Custom Keycloak Authenticator SPI     |
| Validation source          | External REST API (3rd-party)         |
| Login blocked if invalid   | `context.failure()` in SPI            |
| JWT enrichment             | Mappers add roles + circle/branch IDs |
| Optional caching           | Caffeine / Redis                      |
| Secure integration         | Mutual TLS or signed system token     |

---

Would you like me to show the **exact SPI project structure and Keycloak flow XML configuration** (`authenticationFlowExecution` for this step) next?
That’ll make it easy to plug this directly into your running Keycloak instance.







///////////////////////////////////////////



Excellent question — let’s go step-by-step.
We’ll break this into **three parts**:

1. **Maker–Checker-controlled user creation workflow** (business logic outside Keycloak)
2. **How Keycloak login is *blocked until checker approval*** (integration design)
3. **How role and location data flow into JWT claims** after approval.

---

## 🧩 1. Maker–Checker-Controlled User Creation Flow

### ✅ Purpose

Keycloak shouldn’t directly create users as soon as a “maker” submits them — because we need approval, validation (HRMS API, role rules), and mapping.
So we separate *user registration (proposed state)* from *user activation (approved state)*.

### ⚙️ Workflow

#### (A) Maker submission

1. **Maker UI (Angular)** → **User Service API (Spring Boot)** sends a `CreateUserRequest` payload:

   ```json
   {
     "username": "pf12345",
     "userType": "INTERNAL",
     "roleIds": ["COD"],
     "circleId": "C001",
     "raccpMappings": [...],
     "mobile": "...",
     "email": "...",
     "createdBy": "maker123"
   }
   ```

2. User Service performs validations:

   * Internal users: fetch HRMS details using PF ID (email, branch, designation, ESG/EG).
   * External users: verify mobile/email uniqueness.
   * Apply **conditional role rules** (CIT, SIO, etc.).
   * If all validations pass → store record in `pending_user` table with status `PENDING_APPROVAL`.

3. If external user → generate temporary password (hashed) and store it.

   * **No call to Keycloak yet.**
   * Send notification to Checker (via email or dashboard event).

---

#### (B) Checker review

1. Checker logs into UI → sees pending users (filtered by Circle, role, or RACPC).
2. Checker reviews data and either:

   * **Rejects** → status = `REJECTED`, audit logged.
   * **Approves** → triggers backend flow below.

#### (C) On approval

When Checker approves:

1. The User Service:

   * Changes record to status = `APPROVED`.
   * Creates actual user in **Keycloak** via **Admin REST API**:

     * POST `/admin/realms/{realm}/users`
     * Set `enabled=true`.
     * Attributes: branch, circle, role codes, userType, RACPC, etc.
     * Assign realm roles or client roles matching the assigned roles.
     * Optionally, send a temporary password (if external user).

2. Keycloak now has a real user who can authenticate.

3. Publish event to Kafka → for audit and downstream systems.

---

## 🚫 2. How to Block Login Until Checker Approval

There are two clean ways to ensure *only approved users can log in*:

### 🧠 Option 1 — Create user in Keycloak *disabled* (`enabled=false`) during Maker step

* When Maker submits, we still pre-create user in Keycloak (disabled) so the username is reserved.
* On Checker approval, backend calls Keycloak Admin API:

  ```http
  PUT /admin/realms/{realm}/users/{id}
  {
    "enabled": true
  }
  ```
* Disabled users automatically fail authentication (Keycloak rejects login with “Account disabled” error).
* No change needed in Keycloak login flow.

✅ **Pros:** Simple and uses built-in Keycloak behavior.
⚠️ **Cons:** Slightly more API calls if user data is frequently edited before approval.

---

### 🧠 Option 2 — Delay Keycloak creation until approval

* Only store user in local DB (`pending_user` table).
* Keycloak knows nothing until Checker approves.
* On approval → Keycloak Admin API creates a new `enabled=true` user.
* Until then, login attempt fails (Keycloak doesn’t find username).

✅ **Pros:** No inactive accounts clutter Keycloak.
⚠️ **Cons:** Requires handling “user not found” gracefully at login.

---

### 🔐 Recommendation:

* Use **Option 1** for internal users (pre-create disabled users in Keycloak)
* Use **Option 2** for external users (simpler and more secure for onboarding).

---

## 🧾 3. How Roles & Location Details Go Into JWT

### 🔸 Source of Role/Location Data

* When Checker approves, the User Service knows:

  * **Roles:** from Maker’s selection and validation.
  * **Location hierarchy:** Circle, RACPC, Branch, CPC, BPR Center, etc.
* These must appear in the JWT claims so the resource servers can apply authorization rules without extra DB queries.

### 🔸 During Keycloak User Creation (approval stage)

When the User Service calls Keycloak Admin API, it sets:

```json
{
  "attributes": {
    "circleId": "C001",
    "branchId": "B123",
    "raccpId": "RACPC99",
    "userType": "INTERNAL",
    "roleCodes": "COD,CPC_HEAD"
  },
  "realmRoles": ["COD", "CPC_HEAD"]
}
```

Keycloak stores these as user attributes.

---

### 🔸 Mapping attributes into JWT

In the Keycloak **Realm → Client → Mappers**:

1. **Realm Role Mapper**

   * Map assigned realm roles → `roles` claim in JWT.
   * Claim name: `roles`
   * Token Claim JSON Type: `String` or `List`
   * Add to Access Token and ID Token.

2. **User Attribute Mappers** for:

   * `circleId` → claim `circle_id`
   * `branchId` → claim `branch_id`
   * `raccpId` → claim `raccp_id`
   * `userType` → claim `user_type`
   * etc.

3. You can also combine them in one JSON claim using a **script mapper**:

   ```js
   var attr = user.getAttributes();
   var obj = {};
   obj.circleId = attr.get("circleId") != null ? attr.get("circleId").get(0) : null;
   obj.branchId = attr.get("branchId") != null ? attr.get("branchId").get(0) : null;
   obj.roles = user.getRoleMappings().stream().map(r => r.getName()).toArray();
   obj.userType = attr.get("userType") != null ? attr.get("userType").get(0) : null;
   obj.email = user.getEmail();
   obj.username = user.getUsername();
   obj.displayName = user.getFirstName() + ' ' + user.getLastName();
   exports = obj;
   ```

   * Claim name: `user_context`
   * Add to Access Token: ✅ Yes
   * Add to ID Token: ✅ Yes

The resulting JWT will include:

```json
{
  "preferred_username": "pf12345",
  "roles": ["COD", "CPC_HEAD"],
  "user_context": {
    "circleId": "C001",
    "branchId": "B123",
    "raccpId": "RACPC99",
    "userType": "INTERNAL",
    "email": "user@example.com"
  }
}
```

---

## 🔁 End-to-End Example

| Step | Actor           | Action                          | Result                                                                   |
| ---- | --------------- | ------------------------------- | ------------------------------------------------------------------------ |
| 1    | Maker           | Submits internal user `pf12345` | Stored in `pending_user`, Keycloak user created disabled                 |
| 2    | Checker         | Approves                        | Keycloak user enabled, roles and attributes added                        |
| 3    | User            | Logs in                         | Keycloak allows login, validates LDAP, issues JWT with mapped attributes |
| 4    | Resource Server | Validates JWT                   | Uses claims like `roles`, `circle_id` to authorize                       |

---

## ✅ Summary

| Concern                        | Solution                                                                                    |
| ------------------------------ | ------------------------------------------------------------------------------------------- |
| **Maker vs Checker control**   | Store user in pending state; only Checker approval triggers Keycloak creation or activation |
| **Block login until approval** | Keycloak user disabled (enabled=false) or not created until approved                        |
| **Role & location in JWT**     | Add user attributes in Keycloak → map to JWT using mappers or script mapper                 |
| **Authorization checks**       | Resource servers use JWT claims for role and location validation                            |

---

Would you like me to **draw a sequence diagram** showing Maker → Checker → Keycloak → Login → JWT issue flow next?
That visual helps clarify where “approval” gates the login path.










