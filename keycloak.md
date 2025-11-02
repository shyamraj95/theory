
# System Design Technical Document: Secure, Scalable OAuth 2.1 and OpenID Connect Authentication & Authorization System

## 1. Introduction

### 1.1 Purpose
This document outlines the system design for a production-grade, scalable web application implementing OAuth 2.1 and OpenID Connect (OIDC) for authentication and authorization. The system supports internal and external users with enhanced security features, including hybrid encryption, CAPTCHA validation, login restrictions, and a maker-checker workflow for user management. It ensures compliance with best practices for security, scalability, and maintainability.

The architecture is modular, comprising:
- **Authorization Server**: Keycloak for handling OAuth 2.1/OIDC flows.
- **Resource Server**: Spring Boot 3.x (Java 21) backend for API protection and business logic.
- **Frontend**: Angular 20 for user interfaces, leveraging PKCE and DPOP for secure token handling.

Future extensibility includes Single Sign-On (SSO) via Kerberos for internal users.

### 1.2 Scope
- User authentication (LDAP for internal, username/password + OTP for external).
- Authorization with role-based access control (RBAC) and configurable mappings.
- Secure API communications with encryption and token validation.
- Maker-checker workflow for user lifecycle management.
- Caching for performance and security (e.g., CAPTCHA, JWT metadata).
- Scalability via microservices patterns, Kafka for events, and Caffeine for in-memory caching.

### 1.3 Assumptions
- Development uses default credentials (e.g., userid/password) for testing.
- External APIs (HRMS, OTP service) are available and secure.
- Deployment on Kubernetes for horizontal scaling.
- Compliance with GDPR/PCI-DSS for data handling.

## 2. Architecture Overview

### 2.1 High-Level Architecture
The system follows a layered architecture:
- **Presentation Layer**: Angular 20 frontend handles UI, encryption, and OAuth flows.
- **API Gateway Layer**: (Optional, e.g., Spring Cloud Gateway) for routing, rate-limiting.
- **Authorization Layer**: Keycloak manages tokens, user federation (LDAP), and realms.
- **Business Layer**: Spring Boot resource server with services for user management, workflows, and validations.
- **Data Layer**: PostgreSQL (via Spring Data JPA) for users, audits, mappings; Redis for distributed sessions if scaled.
- **Integration Layer**: Kafka for token revocation events; External APIs (HRMS, OTP).
- **Cross-Cutting**: Caffeine caching, hybrid encryption, CAPTCHA generation.

**Diagram Description** (Text-based representation; in production, use PlantUML or Draw.io):
```
[Angular 20 Frontend] <--> [PKCE/DPOP/OAuth Flows] <--> [Keycloak Auth Server]
                          |
                          v
[API Calls (Encrypted)] <--> [Spring Boot Resource Server]
                          |
                          +--> [Caffeine Cache (JWT Metadata, CAPTCHA)]
                          +--> [Spring Data JPA (PostgreSQL)] 
                          +--> [Kafka (Revocation Events)]
                          +--> [External: LDAP/HRMS/OTP API]
```

### 2.2 Data Flow
1. **Login**: Frontend initiates PKCE flow with Keycloak. Payload encrypted (hybrid RSA-AES). CAPTCHA solved and cached.
2. **Token Issuance**: Keycloak issues access/refresh tokens. Metadata (JTI, tabId, IP) cached in resource server.
3. **API Calls**: Frontend sends encrypted requests. Resource server decrypts, validates JWT via JWKS, checks cache for blocks.
4. **User Management**: Maker submits via API/UI → Pending state → Checker approves → Kafka event for role sync.
5. **Logout/Revocation**: Invalidate token, publish Kafka event to block JTI in caches.

### 2.3 Scalability Considerations
- **Horizontal Scaling**: Stateless resource server pods; Keycloak clustered with Infinispan.
- **Load Balancing**: Nginx/Kubernetes Ingress.
- **Caching**: Caffeine for local (TTL-based); Redis for distributed if multi-instance.
- **Async Processing**: Kafka for revocation, OTP delivery.
- **Database Sharding**: By circle/branch for user data.

## 3. Technology Stack

| Component          | Technology/Libraries                          | Purpose |
|--------------------|-----------------------------------------------|---------|
| **Backend (Resource Server)** | Spring Boot 3.x, Java 21                     | API endpoints, business logic |
| **Authorization Server** | Keycloak 24.x (latest as of 2025)            | OAuth 2.1/OIDC, user federation |
| **Frontend**       | Angular 20                                   | UI, PKCE/DPOP flows |
| **Caching**        | Caffeine 3.x                                 | In-memory cache for CAPTCHA, JWT metadata |
| **Database**       | PostgreSQL + Spring Data JPA 3.x             | User data, audits, mappings |
| **LDAP Integration** | Spring LDAP 3.x                             | Internal user auth |
| **Encryption**     | Java Cryptography Extension (JCE)            | RSA-AES hybrid |
| **CAPTCHA**        | Java AWT/Swing (graphics APIs) + Caffeine    | Custom generation/validation |
| **Messaging**      | Kafka 3.x (Spring Kafka)                     | Token revocation events |
| **Other**          | Spring Security 6.x, JJWT 0.12.x             | JWT handling; Stable CAPTCHA (no external lib needed) |
| **Build/Tools**    | Maven 3.9.x, Angular CLI 20.x                | Project management |

**Maven Dependencies (Resource Server - pom.xml snippet)**:
```xml
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-ldap</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.kafka</groupId>
        <artifactId>spring-kafka</artifactId>
    </dependency>
    <dependency>
        <groupId>com.github.ben-manes.caffeine</groupId>
        <artifactId>caffeine</artifactId>
        <version>3.1.8</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.12.3</version>
    </dependency>
    <!-- JJWT Impl -->
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.12.3</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.12.3</version>
    </dependency>
</dependencies>
```

## 4. System Components

### 4.1 Authorization Server (Keycloak)
- **Configuration**: Custom realm with clients for frontend/resource server. Enable PKCE, DPOP. Federate LDAP for internal users.
- **User Federation**: LDAP for internal (Microsoft AD); Database for external.
- **OTP Integration**: Custom SPI for external login (call internal OTP service post-password).
- **Token Settings**: Access token TTL: 15min; Refresh: 1hr. Include custom claims (roles, branch).
- **Project Structure**:
  ```
  keycloak-config/
  ├── realm-export.json (roles, clients, mappers)
  ├── themes/ (custom login theme with CAPTCHA embed)
  └── docker-compose.yml (for dev: Keycloak + Postgres)
  ```
- **Sample Realm Config (JSON snippet for export)**:
  ```json
  {
    "realm": "myrealm",
    "enabled": true,
    "clients": [
      {
        "clientId": "angular-frontend",
        "protocol": "openid-connect",
        "pkceCodeChallengeMethod": "S256",
        "attributes": { "dpop.bound.access.tokens": "true" }
      }
    ],
    "users": [ /* External users in pending state */ ],
    "roles": { "realm": [ "SA", "CA", "Maker", "COD" /* etc. */ ] }
  }
  ```

### 4.2 Resource Server (Spring Boot)
- **JWT Validation**: Use Spring Security OAuth2 Resource Server with JWKS from Keycloak.
- **Encryption Service**: Hybrid RSA-AES for payloads (request: client encrypts AES key with server RSA pub; server decrypts, re-encrypts response with same AES).
- **CAPTCHA Service**: Generate image using Java AWT, store solution in Caffeine (key: sessionId, expire: 5min).
- **User Service**: JPA entities for User, Role, Mapping (Circle, Branch, CPC). Maker-checker via @PreAuthorize and state machine.
- **Kafka Listener**: For revocation events – block JTI in Caffeine.
- **Project Structure**:
  ```
  resource-server/
  ├── src/main/java/com/example/
  │   ├── config/ (SecurityConfig, CacheConfig, EncryptionConfig)
  │   ├── controller/ (UserController, AuthController)
  │   ├── service/ (UserService, CaptchaService, EncryptionService, KafkaRevocationListener)
  │   ├── entity/ (User, Role, AuditLog, LocationMapping)
  │   ├── repository/ (Jpa repos)
  │   └── dto/ (EncryptedPayloadDto)
  ├── src/main/resources/
  │   ├── application.yml (DB, Kafka, Cache configs)
  │   └── schema.sql (Tables: users, audits, mappings)
  └── pom.xml
  ```
- **Key Code Snippets**:

  **SecurityConfig.java** (JWT + Encryption Filter):
  ```java
  @Configuration
  @EnableWebSecurity
  public class SecurityConfig {
      @Bean
      public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
          http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())));
          http.addFilterBefore(new EncryptionFilter(encryptionService), UsernamePasswordAuthenticationFilter.class);
          return http.build();
      }

      @Bean
      public JwtDecoder jwtDecoder() {
          return NimbusJwtDecoder.withJwkSetUri("http://keycloak/realms/myrealm/protocol/openid-connect/certs").build();
      }
  }
  ```

  **EncryptionService.java** (Hybrid RSA-AES):
  ```java
  @Service
  public class EncryptionService {
      private final RSAPublicKey rsaPublicKey; // Load from keystore
      private final RSAPrivateKey rsaPrivateKey;

      public EncryptedPayloadDto encryptPayload(String payload, SecretKey aesKey) throws Exception {
          // AES encrypt payload
          Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
          aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
          byte[] encryptedPayload = aesCipher.doFinal(payload.getBytes());
          // RSA encrypt AES key
          Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
          rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
          byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
          // Add nonce/timestamp for replay protection
          String nonce = UUID.randomUUID().toString();
          long timestamp = System.currentTimeMillis();
          return new EncryptedPayloadDto(encryptedPayload, encryptedAesKey, nonce, timestamp);
      }

      public String decryptPayload(EncryptedPayloadDto dto) throws Exception {
          // Decrypt AES key with RSA private
          Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
          rsaCipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
          byte[] aesKeyBytes = rsaCipher.doFinal(dto.getEncryptedAesKey());
          SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
          // Validate nonce/timestamp (e.g., timestamp > now - 5min)
          if (System.currentTimeMillis() - dto.getTimestamp() > 300000) throw new ReplayAttackException();
          // AES decrypt payload
          Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
          aesCipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, dto.getNonce().getBytes()));
          return new String(aesCipher.doFinal(dto.getEncryptedPayload()));
      }
  }
  ```

  **CaptchaService.java** (Custom with AWT):
  ```java
  @Service
  public class CaptchaService {
      private final Cache<String, String> captchaCache = Caffeine.newBuilder()
          .expireAfterWrite(5, TimeUnit.MINUTES)
          .build();

      public byte[] generateCaptcha() {
          String solution = generateRandomString(6); // e.g., alphanumeric
          BufferedImage img = new BufferedImage(200, 50, BufferedImage.TYPE_INT_RGB);
          Graphics2D g2d = img.createGraphics();
          g2d.setColor(Color.WHITE);
          g2d.fillRect(0, 0, 200, 50);
          g2d.setColor(Color.BLACK);
          g2d.setFont(new Font("Arial", Font.BOLD, 20));
          g2d.drawString(solution, 50, 30); // Distort with lines/noise for security
          g2d.dispose();
          String sessionId = UUID.randomUUID().toString();
          captchaCache.put(sessionId, solution);
          ByteArrayOutputStream baos = new ByteArrayOutputStream();
          ImageIO.write(img, "png", baos);
          return baos.toByteArray();
      }

      public boolean validateCaptcha(String sessionId, String userInput) {
          String solution = captchaCache.getIfPresent(sessionId);
          return solution != null && solution.equalsIgnoreCase(userInput);
      }

      private String generateRandomString(int length) {
          // Implement random gen using SecureRandom
          return new String(new char[length]).replaceAll(".", (Math.random() < 0.5 ? "A" : "a") + (char)(Math.random()*26 + '0'));
      }
  }
  ```

  **UserService.java** (Maker-Checker + HRMS Call):
  ```java
  @Service
  @Transactional
  public class UserService {
      @Autowired private UserRepository userRepo;
      @Autowired private RestTemplate restTemplate; // For HRMS
      @Autowired private KafkaTemplate<String, TokenRevocationEvent> kafkaTemplate;

      @PreAuthorize("hasRole('Maker')")
      public UserDto createUser(UserCreateDto dto, Authentication auth) {
          User user = new User();
          user.setStatus("PENDING");
          if (dto.isInternal()) {
              // Fetch from HRMS
              Map<String, Object> hrmsData = restTemplate.getForObject("http://hrms/api/pf/{pfId}", Map.class, dto.getPfId());
              user.setEmail((String) hrmsData.get("email"));
              // etc.
          } else {
              // Bulk from Excel: Use Apache POI to parse
              // Send temp pass via OTP service
          }
          user.setRoles(dto.getRoles()); // Configurable mapping
          userRepo.save(user);
          return UserDto.from(user);
      }

      @PreAuthorize("hasRole('Checker') and @circleValidator.isValid(auth.name(), user.circle)")
      public void approveUser(Long userId) {
          User user = userRepo.findById(userId).orElseThrow();
          user.setStatus("ACTIVE");
          // Validate roles: e.g., for CIT, check branch match via external API
          if (user.hasRole("CIT")) {
              validateRoleExternal(user); // Call API
          }
          userRepo.save(user);
          // Kafka event for sync
      }

      // Login restrictions: Track in AuditLog
      public void handleLoginAttempt(String username, boolean success) {
          AuditLog log = new AuditLog(username, success ? "SUCCESS" : "FAIL");
          if (!success) {
              long failsToday = auditRepo.countFailsToday(username);
              if (failsToday >= 3) {
                  blockUser(username); // Set blocked_until = next day
              }
          }
          auditRepo.save(log);
      }

      // One session: On new login, invalidate prev via Keycloak admin API or cache block
      private void invalidatePreviousSessions(String username) {
          // Call Keycloak to revoke user sessions
      }
  }
  ```

  **KafkaRevocationListener.java**:
  ```java
  @KafkaListener(topics = "token-revocation")
  public void handleRevocation(TokenRevocationEvent event) {
      blockedTokensCache.put(event.getJti(), true, event.getExpiry()); // Caffeine
  }
  ```

  **Application.yml**:
  ```yaml
  spring:
    datasource:
      url: jdbc:postgresql://localhost:5432/authdb
    jpa:
      hibernate:
        ddl-auto: validate
    kafka:
      bootstrap-servers: localhost:9092
  keycloak:
    realm: myrealm
    auth-server-url: http://localhost:8080
  caffeine:
    spec: maximumSize=500,expireAfterWrite=15m  # For JWT metadata
  ```

### 4.3 Frontend (Angular 20)
- **OAuth Flow**: Use @angular/oauth2-oidc for PKCE + DPOP. Auto-refresh tokens.
- **Encryption**: Web Crypto API for AES; RSA via jsrsasign lib.
- **CAPTCHA**: Display image, input validation pre-submit.
- **API Calls**: Encrypt payloads for POST/PUT/DELETE; Add nonce/timestamp.
- **Session Management**: Store tabId/IP in localStorage; Send on requests for validation.
- **Project Structure**:
  ```
  angular-frontend/
  ├── src/app/
  │   ├── auth/ (auth.service.ts, pkce-config.ts)
  │   ├── services/ (encryption.service.ts, captcha.service.ts, user.service.ts)
  │   ├── components/ (login.component.ts, maker-form.component.ts)
  │   └── models/ (user.dto.ts)
  ├── angular.json
  └── package.json
  ```
- **Key Code Snippets** (TypeScript):

  **auth.service.ts** (PKCE + DPOP):
  ```typescript
  import { OAuthService } from 'angular-oauth2-oidc';
  import { HttpClient } from '@angular/common/http';

  @Injectable()
  export class AuthService {
    constructor(private oauth: OAuthService, private http: HttpClient) {
      this.oauth.configure({
        issuer: 'http://keycloak/realms/myrealm',
        clientId: 'angular-frontend',
        responseType: 'code',
        scope: 'openid profile email',
        showDebugInformation: true,
        requireHttps: false, // Dev only
        dpop: true // DPOP binding
      });
      this.oauth.loadDiscoveryDocumentAndTryLogin();
    }

    login() {
      this.oauth.initCodeFlow();
    }

    refreshToken() {
      return this.oauth.refreshToken();
    }

    getAccessToken() {
      return this.oauth.getAccessToken();
    }
  }
  ```

  **encryption.service.ts** (Hybrid):
  ```typescript
  import * as KJUR from 'jsrsasign'; // For RSA

  @Injectable()
  export class EncryptionService {
    private rsaPublicKey: string; // PEM from server

    async encryptPayload(payload: string): Promise<EncryptedPayload> {
      const aesKey = await window.crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt', 'decrypt']);
      const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
      // AES encrypt
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encryptedPayload = await window.crypto.subtle.encrypt({name: 'AES-GCM', iv}, aesKey, new TextEncoder().encode(payload));
      // RSA encrypt AES key
      const rsaKey = KJUR.KEYUTIL.getKey(this.rsaPublicKey);
      const encryptedAesKey = rsaKey.encrypt(String.fromCharCode(...new Uint8Array(exportedAesKey)));
      const nonce = crypto.randomUUID();
      const timestamp = Date.now();
      return { encryptedPayload: Array.from(new Uint8Array(encryptedPayload)), encryptedAesKey, nonce, timestamp, iv: Array.from(iv) };
    }

    // Decrypt response similarly (server sends AES-encrypted response)
  }
  ```

  **user.service.ts** (API Calls with Encryption):
  ```typescript
  @Injectable()
  export class UserService {
    constructor(private http: HttpClient, private encService: EncryptionService, private auth: AuthService) {}

    createUser(userData: any) {
      const encrypted = await this.encService.encryptPayload(JSON.stringify(userData));
      const tabId = localStorage.getItem('tabId');
      const ip = await this.getClientIp(); // Fetch IP
      return this.http.post('/api/users', { payload: encrypted, metadata: { tabId, ip } }, {
        headers: { Authorization: `DPoP ${this.auth.getAccessToken()}`, 'Content-Type': 'application/json' }
      });
    }

    // CAPTCHA integration in login component
  }
  ```

  **package.json Snippet**:
  ```json
  {
    "dependencies": {
      "@angular/core": "^20.0.0",
      "angular-oauth2-oidc": "^20.0.0",
      "jsrsasign": "^10.8.6"
    }
  }
  ```

## 5. Security Features

### 5.1 Encryption and Validation
- **Requests**: Client encrypts payload (AES), wraps AES key (RSA pub). Add nonce/timestamp; server validates replay (<5min window).
- **Responses**: Server re-encrypts with provided AES key.
- **Tokens**: DPOP for binding; Cache JTI + tabId/IP in Caffeine (expire with token TTL). Reject mismatches.
- **API Filter**: Custom filter decrypts/validates pre-controller.

### 5.2 CAPTCHA
- Generated server-side (AWT image), solution cached (Caffeine). Frontend displays base64 image.
- Mandatory for all logins; validate on submit.

### 5.3 Login Restrictions
- **Wrong Attempts**: Audit table tracks per-user/day. Block via flag (auto-unblock cron job).
- **Single Session**: On new login, prompt consent → Revoke prior via Keycloak API.
- **First-Time Reset**: External users redirected post-login.
- **Role Validation**: External API call for COD/CPC Head; configurable via properties.

### 5.4 Token Handling
- **Resource Server**: Validate signature/expiry via JWKS. Check Caffeine for block.
- **Revocation**: Logout → Publish Kafka event (JTI). Suspicious (e.g., IP mismatch) → Auto-block + event.
- **Best Practices**: HTTPS only, CORS restricted, OWASP Top 10 mitigations (e.g., CSRF via state param).

## 6. Maker-Checker Workflow
- **States**: PENDING → APPROVED/REJECTED.
- **Maker**: API/UI form; Internal: HRMS fetch; External: Bulk Excel (POI parser). Assign roles, map locations (e.g., User → CPC).
- **Mappings** (JPA Entities):
  - Circle → Networks → Modules → Branches → CPCs.
  - Conditional: CIT/SIO branch/ESG/EG code checks.
- **Checker**: Circle-specific approval. Updates auto-approved (no workflow).
- **Bulk**: Excel upload → Parse → Queue for OTP temp pass.

**Entity Example (LocationMapping.java)**:
```java
@Entity
public class LocationMapping {
    @Id private Long id;
    @ManyToOne private Circle circle;
    @OneToMany private List<Network> networks;
    // Configurable: CIT validation logic in service
}
```

## 7. User Management and Roles
- **Types**: Internal (LDAP fetch), External (DB + OTP).
- **Roles**: SA, CA, Maker, Checker, DASHBOARD, COD, etc. Multi-role per user; Configurable permissions (e.g., via Keycloak groups).
- **Mappings**:
  - User 1:1 CPC (COD/NCOD/CIT/CPC Head).
  - User M:1 BPR (SIO).
  - User M:M CPC (Advocate/Valuer/Vendors).
  - Vendors 1:M Employees.
- **Audit**: All actions logged (JPA).

## 8. Caching and Performance
- **Caffeine Config**: TTL for CAPTCHA (5min), JWT metadata (token expiry), blocks (1day).
- **Eviction**: Size-based (500 entries max).
- **Distributed**: If scaled, sync via Kafka.

## 9. Best Practices and Production-Readiness
- **Clean Architecture**: Layers (Controller → Service → Repo); DTOs for APIs.
- **Testing**: JUnit 5, Mockito; Integration with Testcontainers (Keycloak/Postgres).
- **Monitoring**: Spring Actuator + Prometheus; Logs via SLF4J.
- **CI/CD**: GitHub Actions; Dockerized.
- **Security Scans**: OWASP Dependency-Check, SonarQube.
- **Error Handling**: Global @ControllerAdvice; Custom exceptions (e.g., BlockedTokenException).

## 10. Future Plans
- **SSO**: Integrate Kerberos for internal users (Spring Security Kerberos module).
- **Extensions**: Multi-factor (TOTP), Audit dashboards, AI-based anomaly detection.

This design ensures a robust, secure system. For full implementation, refer to code repos (e.g., GitHub). Contact for clarifications. 

**Version**: 1.0 | **Date**: October 29, 2025 | **Author**: Grok System Design





//////////////////




### Choice of Libraries for Encryption in Angular Frontend

In the system design document, the Angular frontend code snippet for encryption used the Web Crypto API (`window.crypto.subtle`) for AES-GCM encryption (which is native, secure, and performant) but fell back to `jsrsasign` (a pure JavaScript library) specifically for RSA encryption of the AES key. Here's why that choice was made in the example, and why we can (and should) align it fully with Web Crypto:

#### Why jsrsasign for RSA?
- **Ease of Use in Examples**: `jsrsasign` handles RSA operations (like OAEP padding for hybrid encryption) with straightforward synchronous APIs and easy PEM key import/export. It's battle-tested for browser environments and doesn't require dealing with async promises or subtle key formats right away. This made the code snippet more concise for illustration.
- **Legacy Compatibility**: In older browsers or environments without full Web Crypto support (e.g., some IE/Edge legacy modes), `jsrsasign` acts as a polyfill. However, as of 2025, modern browsers (Chrome 37+, Firefox 34+, Safari 7+) fully support Web Crypto RSA-OAEP, so this is rarely needed.
- **Handling PEM Keys**: `jsrsasign` excels at parsing PEM-formatted RSA public keys (common for server-provided keys), converting them to usable formats without extra steps.

#### Why Not Use Web Crypto for Both AES and RSA?
You're absolutely right—Web Crypto API can handle **both** AES (GCM/CBC modes) and RSA (OAEP/PKCS#1) natively, and it's the **recommended approach** for production. Reasons to prefer it over `jsrsasign`:
- **Security**: It's a low-level, W3C-standard API with built-in hardware acceleration (e.g., via TPM or Secure Enclave), reducing attack surface. No third-party lib dependencies means fewer vulnerabilities (e.g., jsrsasign has had minor CVEs in the past).
- **Performance**: Async operations are efficient; no JS overhead.
- **Consistency**: Using one API for the entire hybrid flow simplifies code and maintenance.
- **FIPS Compliance**: Easier to audit for standards like FIPS 140-2 if needed.

**Updated Recommendation**: Switch to full Web Crypto for RSA too. Here's a revised `encryption.service.ts` snippet demonstrating it (async, but handles the hybrid flow cleanly):

```typescript
import * as KJUR from 'jsrsasign'; // Only for initial PEM import if needed; can be replaced with pure Web Crypto

@Injectable()
export class EncryptionService {
  private rsaPublicKey: CryptoKey; // Imported RSA public key

  async initRsaKey(pemPublicKey: string) {
    // Import PEM to Web Crypto (using a helper or TextEncoder; for simplicity, use a lib like 'pem2jwk' if needed, but here's a basic approach)
    const jwk = await this.pemToJwk(pemPublicKey); // Implement or use a small util
    this.rsaPublicKey = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
  }

  private async pemToJwk(pem: string): Promise<JsonWebKey> {
    // Basic PEM to JWK conversion logic (strip headers, base64 decode, etc.)
    // For production, use a lib like 'node-jose' or inline implementation
    // Example stub:
    const binaryDer = atob(pem.replace(/----BEGIN PUBLIC KEY----|-----END PUBLIC KEY-----|\n/g, ''));
    // ... (full impl: https://github.com/pedrouid/pem2jwk or similar)
    return { /* JWK object */ };
  }

  async encryptPayload(payload: string): Promise<EncryptedPayload> {
    // Generate AES key
    const aesKey = await window.crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    const exportedAesKey = await window.crypto.subtle.exportKey('raw', aesKey);

    // AES encrypt payload
    const iv = window.crypto.subtle.generateRandom(12); // Uint8Array
    const encryptedPayload = await window.crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      new TextEncoder().encode(payload)
    );

    // RSA encrypt AES key
    const encryptedAesKey = await window.crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      this.rsaPublicKey,
      exportedAesKey
    );

    const nonce = crypto.randomUUID();
    const timestamp = Date.now();
    return {
      encryptedPayload: Array.from(new Uint8Array(encryptedPayload)),
      encryptedAesKey: Array.from(new Uint8Array(encryptedAesKey)),
      nonce,
      timestamp,
      iv: Array.from(iv)
    };
  }

  // Decrypt response (similarly with provided AES key)
  async decryptResponse(encryptedResponse: Uint8Array, aesKeyRaw: Uint8Array, iv: Uint8Array): Promise<string> {
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      aesKeyRaw,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const decrypted = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      aesKey,
      encryptedResponse
    );
    return new TextDecoder().decode(decrypted);
  }
}
```

This aligns AES and RSA under one API. For PEM import, a small utility (e.g., `pem-jwk` npm package) can handle it without full `jsrsasign`. Drop `jsrsasign` dependency to minimize bundle size.

#### Why Not Use Keycloak JS Adapter?
- **What It Is**: The official `@keycloak/keycloak-js` adapter is a lightweight library for vanilla JS/SPA apps to handle OIDC flows (login, token refresh, logout) with Keycloak. It's great for simple setups.
- **Why angular-oauth2-oidc Instead?**
  - **Angular-Specific Integration**: `angular-oauth2-oidc` is tailored for Angular (v20+), providing seamless hooks into Angular's HttpClient, guards, resolvers, and router (e.g., auto-redirect on 401s). It supports PKCE, DPOP, silent renew, and custom claims out-of-the-box—perfect for the required secure flows.
  - **Broader OIDC Support**: It's not Keycloak-only; it works with any OIDC provider, making the app more portable. Keycloak JS is Keycloak-centric and requires more boilerplate for Angular (e.g., manual zone.js patching).
  - **Features for This System**: It natively handles token metadata caching, refresh with rotation, and DPOP binding, which aligns with the design's JWT validation and revocation needs. Keycloak JS would need extensions for full Angular lifecycle management.
  - **Trade-offs**: If the app were non-Angular (e.g., React/Vanilla), Keycloak JS would be ideal. For Angular, `angular-oauth2-oidc` is the community-recommended choice (endorsed in Keycloak docs).

If you prefer Keycloak JS, we can swap: Install `@keycloak/keycloak-js-adapter@latest`, init with `new Keycloak({ url: '...', realm: '...', clientId: '...' })`, and handle events manually. But for Angular 20, the current choice is optimal.

### Full Explanation of Keycloak SPIs and Configuration

Keycloak (latest v25.x as of Oct 2025) uses **Service Provider Interfaces (SPIs)** for extensibility, allowing custom Java providers to hook into core behaviors like authentication, user storage, events, and more. SPIs follow a factory-provider pattern: A `ProviderFactory` creates `Provider` instances per request, injected via `KeycloakSession`. They're deployed as JARs in the `providers/` dir, followed by `kc.sh build` (Quarkus-based since v17+).

#### Overview of SPIs
SPIs are grouped by category. Below is a table summarizing all major ones (based on official docs), their purposes, key interfaces, and config notes. New in 2025: Enhanced stream-based queries in User Storage for large-scale performance; no major new SPIs, but Script Providers are now stable (out of preview).

| Category | SPI Name | Purpose | Key Interfaces/Classes | Configuration/Notes |
|----------|----------|---------|------------------------|---------------------|
| **Authentication** | Authenticator | Custom login steps (e.g., OTP, CAPTCHA integration). | `Authenticator`, `AuthenticatorFactory` | Bind to flows in Admin Console > Authentication > Flows. Supports conditional execution. |
| **Authentication** | Required Action | Post-login actions (e.g., first-time password reset). | `RequiredActionProvider`, `RequiredActionFactory` | Assign per user/realm in Admin Console > Users > Required Actions. |
| **Authentication** | Form Action | Extend forms (e.g., registration validation). | `FormAction`, `FormActionFactory` | Used in registration/email flows; config via `Config.Scope`. |
| **Credentials** | Credential Provider | Custom credential types (e.g., TOTP, custom hashes). | `CredentialProvider`, `CredentialProviderFactory`, `CredentialModel` | Integrated with authenticators; validate via `CredentialInputValidator`. |
| **User Storage/Federation** | User Storage | Integrate external stores (LDAP, DB); supports read/write/sync. | `UserStorageProvider`, `UserLookupProvider`, `UserQueryProvider` (with Streams for large data), `CredentialInputValidator` | Realm > User Federation > Add Provider (e.g., LDAP config: bind DN, users DN). Modes: Import (local copy) or non-import (federated). |
| **User Storage/Federation** | Federated Storage | Augment external users with Keycloak features (roles/groups). | `UserFederatedStorageProvider` | Auto-linked via storage ID (`f:{componentId}:{externalId}`); sync via `ImportSynchronization`. |
| **Events** | Event Listener | React to events (login, logout, token revocation). | `EventListenerProvider`, `EventListenerProviderFactory` | Realm > Events > Config (e.g., save events to DB/Kafka). Custom: Publish to external systems. |
| **Client Authentication** | Client Authenticator | Custom client auth (beyond client_secret/JWT, e.g., mTLS). | `ClientAuthenticator`, `ClientAuthenticatorFactory` | Client > Settings > Authentication Flow; server-side factory override. |
| **Tokens** | Action Token Handler | Handle JWT action tokens (e.g., reset links, verification). | `ActionTokenHandler`, `ActionTokenHandlerFactory`, `DefaultActionToken` | Endpoint: `/realms/{realm}/login-actions/action-token`; claims like `typ`, `sub`. Extend for custom fields. |
| **SAML** | SAML Role Mappings | Map SAML roles to app roles in SP env. | `RoleMappingsProvider` | Config in `keycloak-saml.xml` or subsystem; custom via service files. |
| **Secrets** | Vault | Fetch secrets from external vaults (HashiCorp, AWS). | `VaultProvider`, `VaultProviderFactory` | Realm-isolated; access via `session.vault().getSecret("key")`. Config: Provider-specific props. |
| **Themes** | Theme Selector | Dynamic theme selection (login, account console). | `ThemeSelectorProvider`, `ThemeSelectorProviderFactory` | `--spi-theme-selector-{id}-theme=fixed-{name}`; themes in `themes/` or JARs. |
| **Scripts** | Script Providers | JS-based custom logic (authenticators, policies, mappers). | N/A (JS functions: `authenticate()`, `authorize()`) | Enable `--features=scripts`; upload scripts via Admin Console > Realm > Scripts. Stable in 2025. |
| **Custom/Extensibility** | Custom SPI | Define entirely new SPIs (e.g., for business logic). | `Spi`, `Provider` | Implement `Spi` metadata; use `JpaEntityProvider` for DB extensions (Liquibase changelogs). |
| **Caching** | User Cache | Manage user session caching. | `UserCacheProvider` | Local/in-memory; cluster invalidation. Config: TTL via realm settings. |

- **Core Mechanics**:
  - **Provider Lifecycle**: Factories use `postInit()`, `init(Config.Scope scope)` for config (e.g., `--spi-authenticator-otp-enabled=true`). Providers get `KeycloakSession` for context (e.g., `session.users()`).
  - **Multiple vs. Single**: Most (e.g., Event Listener) support multiples (chained); singles (e.g., Hostname) use one default.
  - **Ordering/Overrides**: Implement `order()` in factory; match `getId()` to built-in (e.g., "basic-auth" for override).
  - **Disabling**: `--spi-{name}-{providerId}-enabled=false`.

#### Implementing and Deploying Custom SPIs
1. **Code**: Extend base classes (e.g., `AbstractAuthenticator` for auth). Add `@Override` methods like `authenticate()`.
   - Example (OTP Authenticator Factory):
     ```java
     public class OtpAuthenticatorFactory implements AuthenticatorFactory {
         @Override
         public String getId() { return "otp-auth"; }
         @Override
         public Authenticator create(KeycloakSession session) { return new OtpAuthenticator(); }
         // Config: scope.getBoolean("enabled", true)
     }
     ```
2. **META-INF/services**: Create file `META-INF/services/org.keycloak.authentication.AuthenticatorFactory` with `com.example.OtpAuthenticatorFactory`.
3. **Build/Deploy**: `mvn clean package` → JAR to `providers/`. Run `kc.sh build` (caches optimized build).
4. **Testing**: Use `KeycloakSessionMock` in unit tests; integration via embedded Keycloak.
5. **Quarkus Notes (2025)**: No CDI/EJB; use plain POJOs. Dependencies via `keycloak-bom` in `pom.xml`.

#### Keycloak Configuration Details
- **Realms**: Isolated tenants (Users, Clients, Roles). Create via Admin Console or REST (`POST /admin/realms`). Config: Events, Login (e.g., brute force detection), Tokens (TTL, keys).
- **Clients**: OIDC/SAML apps. Settings: Client ID, Secret, Flows (PKCE required for public clients), Mappers (custom claims like roles/branch). For this system: Enable DPOP (`attributes.dpop-bound-access-tokens=true`), PKCE (`pkceCodeChallengeMethod=S256`).
- **Themes**: Custom UI (login/register). Deploy to `themes/{type}/{name}/` (e.g., `login/mytheme/login.ftl`). Selector SPI for dynamic choice.
- **User Federation**: Realm > User Federation > Add (e.g., LDAP: Connection URL `ldap://ad.example.com`, Bind Type). Sync: Full/Changed Users. For internal users: Federate Microsoft AD via LDAP provider.
- **Global Config**: CLI flags (`--hostname-strict=false`), `conf/keycloak.conf` (DB, features like `--features=scripts`), or Env vars.
- **OTP/Custom Flows**: For external users, extend login flow with FormAction for OTP (call internal service). Cache solutions (e.g., CAPTCHA) via session attributes.
- **Token Revocation**: Use Event Listener SPI to publish Kafka events on `LOGOUT`/`REFRESH_TOKEN`; integrate with resource server's Caffeine.

This setup fits the design: Custom Authenticator for CAPTCHA/OTP, User Storage for LDAP, Event Listener for revocation. For full code, extend the Keycloak config repo from the doc. Let me know if you need a specific SPI implementation!
\


//////////






Yes, Keycloak can handle both CAPTCHA and OTP (One-Time Password) as part of its authentication flows, though the level of native support varies. I'll break it down below with details on implementation.

### CAPTCHA Support
Keycloak provides built-in integration with Google reCAPTCHA to prevent bots during user registration, login, and other forms. You can enable it realm-wide or per-flow:
- **Configuration**: Go to the Admin Console > Realm Settings > Login tab, enable "reCAPTCHA" under "Registration" or "Login" options. You'll need a Google reCAPTCHA site key and secret (v2 or v3). This adds an invisible or checkbox challenge to forms.
- **Customization**: For non-Google options (e.g., hCaptcha or custom CAPTCHA), use Service Provider Interfaces (SPIs) like Form Actions or Authenticators to inject challenges. Plugins like Friendly Captcha or hCaptcha extensions are available for privacy-focused alternatives.
- **Use Cases**: Ideal for filtering spam in self-registration or brute-force login attempts. It's configurable to be optional or required based on flows.

This makes CAPTCHA straightforward for production setups without heavy custom code.

### OTP Support
Keycloak has strong native support for OTP as part of multi-factor authentication (MFA), primarily for TOTP (Time-based OTP) and HOTP via apps like Google Authenticator or FreeOTP. For SMS/email OTP, it requires extensions.
- **Native TOTP/HOTP**:
  - **Setup**: In Admin Console > Authentication > Flows, add "OTP Form" to your browser flow (e.g., after username/password). Configure OTP Policy under Authentication > Policies: Set hash algorithm (e.g., SHA1), digits (6), and look-ahead window (1).
  - **User Enrollment**: Assign "Configure OTP" as a required action for users (Users > Details > Required User Actions). Users scan a QR code to set up in their authenticator app.
  - **Flows**: Supports conditional MFA (e.g., required only for certain roles or IPs).
- **SMS/Email OTP**:
  - Not built-in, but implement via custom Authenticators or Form Actions SPIs. For example, after password validation, send OTP via an internal service (e.g., Twilio) and validate user input. Community guides and extensions (like OTP+) simplify this.
- **Policies and Security**: Realm-level OTP policies enforce validation rules, and it integrates with brute-force detection.

In summary, CAPTCHA is plug-and-play with reCAPTCHA, while OTP is robust for app-based 2FA out-of-the-box but extensible for SMS/email—perfect for your external user flows in the system design. For the latest (Keycloak 26+ as of 2025), check the official docs for any Quarkus-specific tweaks. If you need code snippets for custom SPIs, let me know!



///////////////////////



### Customizing Keycloak's Built-in Login Page for Encryption, OTP, CAPTCHA, and Styling

Since you're sticking with Keycloak's hosted login page (no custom SPA UI), that's the right call for security and simplicity—it keeps credential handling server-side. You can fully customize it using **Keycloak themes** (Freemarker templates + CSS/JS) for styling and client-side logic (e.g., encryption), plus **SPIs** for server-side features like OTP/CAPTCHA validation. This integrates seamlessly with your Angular SPA's PKCE flow: the SPA redirects to Keycloak's login, user authenticates there, and redirects back with tokens.

Below, I'll outline implementation for each feature, with steps and snippets. Assume you're working in a custom theme (e.g., `my-theme` in `themes/login/my-theme/`).

#### 1. **Styling the Login Page**
   - **Approach**: Override Freemarker templates and add custom CSS/JS. No SPIs needed.
   - **Steps**:
     1. Create a theme: In Keycloak's `themes/` dir, copy the `keycloak` theme to `my-theme` (for login type).
     2. Edit `login.ftl` (main template) for layout changes (e.g., add branding).
     3. Add CSS to `theme.properties` and `resources/css/login.css`.
     4. Assign theme: Admin Console > Realm Settings > Themes > Login Theme = `my-theme`.
   - **Example Snippet** (`login.ftl` for custom header):
     ```ftl
     <#import "template.ftl" as layout>
     <@layout.registrationLayout displayInfo=true; section>
         <#if section = "header">
             <div id="kc-header" class="${properties.kcHeaderClass!}">
                 <div id="kc-header-wrapper" class="${properties.kcHeaderWrapperClass!}">
                     <img src="${url.resourcesPath}/img/my-logo.png" alt="My App" />
                     <h1>My Secure App</h1>
                 </div>
             </div>
         <#elseif section = "form">
             <!-- Default form with custom classes -->
             <div class="custom-form-wrapper">
                 <form id="kc-form-login" action="${url.loginAction}" method="post">
                     <!-- Username/Password fields with custom styling -->
                     <input type="text" id="username" class="custom-input" name="username" />
                     <input type="password" id="password" class="custom-input" name="password" />
                 </form>
             </div>
         </#if>
     </@layout.registrationLayout>
     ```
   - **CSS Example** (`resources/css/login.css`):
     ```css
     .custom-form-wrapper { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 2rem; border-radius: 10px; }
     .custom-input { width: 100%; padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
     ```
   - **Result**: Branded, responsive page without touching Angular.

#### 2. **Adding CAPTCHA**
   - **Approach**: Use Keycloak's native Google reCAPTCHA (v2/v3) for easy integration, or custom via SPI for your Java AWT-generated CAPTCHA.
   - **Native reCAPTCHA (Recommended for Quick Start)**:
     1. Admin Console > Realm Settings > Login > Enable "reCAPTCHA" > Enter site/secret keys.
     2. It auto-injects into `login.ftl` (checkbox or invisible challenge).
     3. For styling: Override the reCAPTCHA div in CSS (e.g., `.g-recaptcha { transform: scale(0.8); }`).
   - **Custom CAPTCHA (Ties to Your Caffeine-Cached AWT Image)**:
     1. Implement a **FormAction SPI** to generate/serve CAPTCHA image and validate against Caffeine cache.
     2. In theme, add JS to fetch/display image and submit solution.
   - **Example SPI Snippet** (CustomCaptchaFormAction.java – extends FormAction):
     ```java
     public class CustomCaptchaFormAction extends AbstractFormAction {
         @Override
         public void validate(ValidationContext context) {
             String solution = context.getHttpRequest().getDecodedFormParameters().getFirst("captcha_solution");
             String sessionId = context.getSession().getId();
             String cachedSolution = captchaService.getCachedSolution(sessionId); // Caffeine lookup
             if (!solution.equals(cachedSolution)) {
                 context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                 response.setError("Invalid CAPTCHA");
                 return;
             }
             // Proceed to next step
             context.success();
         }

         @Override
         public void buildPage(FormContext context) {
             // Generate image URL or base64
             String captchaImage = captchaService.generateAndCache(sessionId); // Returns base64
             context.getContext().setAttribute("captchaImage", captchaImage);
         }
     }
     ```
     - Factory/Registration: As in prior SPI examples.
     - In `login.ftl`: `<img src="data:image/png;base64,${captchaImage}" /> <input name="captcha_solution" />`.
   - **Integration**: Add the FormAction to your browser flow (Admin > Authentication > Flows > Browser > Add execution = Custom CAPTCHA).

#### 3. **Adding OTP**
   - **Approach**: Use built-in TOTP for app-based OTP, or custom FormAction SPI for email/SMS (integrate your internal service).
   - **Built-in TOTP (Quick)**:
     1. Admin > Authentication > Flows > Add "OTP Form" after password step.
     2. Users enroll via "Configure OTP" required action (QR code in theme).
     3. Styling: Customize `otp.ftl` template similarly to `login.ftl`.
   - **Custom SMS/Email OTP (For External Users)**:
     1. After password validation, use FormAction to send OTP via your service, then prompt in a custom form.
   - **Example SPI Snippet** (OtpFormAction.java):
     ```java
     public class OtpFormAction extends AbstractFormAction {
         @Override
         public void buildPage(FormContext context) {
             // If post-password, send OTP
             if (context.getAuthenticationSession().getAuthNote("passwordValidated") != null) {
                 String username = context.getUser() != null ? context.getUser().getUsername() : "";
                 String otp = otpService.generateAndSend(username); // Call internal SMS/Email
                 context.getAuthenticationSession().setAuthNote("pendingOtp", otp);
                 context.getContext().setAttribute("otpSent", true);
             }
         }

         @Override
         public void validate(ValidationContext context) {
             String userOtp = context.getHttpRequest().getDecodedFormParameters().getFirst("otp");
             String pendingOtp = context.getAuthenticationSession().getAuthNote("pendingOtp");
             if (!userOtp.equals(pendingOtp)) {
                 context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                 return;
             }
             context.success();
         }
     }
     ```
     - In `login-otp.ftl` (custom template): `<input name="otp" placeholder="Enter OTP" />`.
     - Flow: Insert after "Username Password Form" in browser flow.

#### 4. **Adding Encryption to Login Payload**
   - **Approach**: Since the form submits to Keycloak's server-side endpoint, add client-side JS in the theme to encrypt the payload (hybrid RSA-AES) before POST. Fetch public key from Keycloak (e.g., via a custom endpoint or JWKS). This mirrors your resource server encryption but for auth.
   - **Challenges**: Keycloak doesn't natively encrypt forms, so JS handles it. Use Web Crypto API (no libs needed).
   - **Steps**:
     1. Add JS to theme's `resources/js/login.js`.
     2. Override form submit in `login.ftl`: `<form onsubmit="encryptAndSubmit(event)">`.
     3. Server-side: Extend Keycloak's login action to decrypt (custom Authenticator SPI).
   - **Example JS Snippet** (`login.js`):
     ```javascript
     async function encryptAndSubmit(event) {
         event.preventDefault();
         const form = event.target;
         const username = form.username.value;
         const password = form.password.value;
         const captcha = form.captcha_solution?.value;
         const otp = form.otp?.value;

         const payload = JSON.stringify({ username, password, captcha, otp });
         // Fetch RSA pub key (e.g., from /jwks or custom endpoint)
         const pubKeyResponse = await fetch('/realms/myrealm/protocol/openid-connect/certs');
         const pubKey = await pubKeyResponse.json(); // Use first key or custom

         // Hybrid encrypt (Web Crypto)
         const aesKey = await window.crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
         const iv = window.crypto.subtle.generateRandom(12);
         const encryptedPayload = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(payload));

         const exportedAes = await window.crypto.subtle.exportKey('raw', aesKey);
         const rsaKey = await window.crypto.subtle.importKey('jwk', pubKey.keys[0], { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
         const encryptedAesKey = await window.crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKey, exportedAes);

         // Submit encrypted form data
         const formData = new FormData();
         formData.append('encrypted_payload', btoa(String.fromCharCode(...new Uint8Array(encryptedPayload))));
         formData.append('encrypted_aes_key', btoa(String.fromCharCode(...new Uint8Array(encryptedAesKey))));
         formData.append('iv', btoa(String.fromCharCode(...new Uint8Array(iv))));
         formData.append('nonce', crypto.randomUUID());
         formData.append('timestamp', Date.now());

         fetch(form.action, { method: 'POST', body: formData }).then(() => location.reload());
     }
     ```
   - **Server-Side Decryption**: In a custom `UsernamePasswordForm` (Authenticator SPI override):
     ```java
     // In validate() method
     String encryptedPayload = formData.getFirst("encrypted_payload");
     // Decrypt using RSA private key (from Keycloak's key store) and provided AES/IV
     // Similar to your EncryptionService in Spring Boot
     String decrypted = encryptionService.decryptPayload(encryptedPayload, encryptedAesKey, iv);
     JsonNode json = objectMapper.readTree(decrypted);
     String username = json.get("username").asText();
     // Proceed with auth
     ```
   - **Note**: For replay protection, validate nonce/timestamp server-side. Test thoroughly—encryption adds latency.

### Integration with Your System
- **Flow Update**: In the Mermaid diagram (from prior), the login redirect (step 4) now includes these custom elements in Keycloak's page.
- **Testing**: Use Keycloak's dev mode (`kc.sh start-dev`) with theme enabled. Ensure Angular's redirect URI matches.
- **Best Practices**: Keep JS minimal (bundle via theme resources). For production, audit for OWASP (e.g., secure key handling). If encryption feels heavy for login, consider it optional here and enforce on resource server APIs only.

This keeps everything in Keycloak without SPA custom UI. If you need full SPI code or theme ZIP, let me know!






//////////////////////////


# OAuth 2.1/OIDC Authentication & Authorization System
## Technical Design Document v1.0

---

## Table of Contents
1. [System Overview](#1-system-overview)
2. [Architecture Design](#2-architecture-design)
3. [Technology Stack](#3-technology-stack)
4. [Security Implementation](#4-security-implementation)
5. [Database Design](#5-database-design)
6. [Authentication Flows](#6-authentication-flows)
7. [API Specifications](#7-api-specifications)
8. [Code Implementation](#8-code-implementation)
9. [Deployment Architecture](#9-deployment-architecture)
10. [Monitoring & Operations](#10-monitoring--operations)

---

## 1. System Overview

### 1.1 Purpose
Design and implement a production-grade authentication and authorization system supporting:
- Internal users (LDAP/Active Directory)
- External users (Username/Password + OTP)
- OAuth 2.1 with PKCE and DPoP
- OpenID Connect
- Maker-Checker workflow for user management
- Complex organizational hierarchy mapping

### 1.2 Key Features
- **Multi-tenant User Management**: Internal (LDAP) and External (DB) users
- **Custom CAPTCHA**: Java-based with Caffeine caching
- **Hybrid Encryption**: RSA-AES for request/response payloads
- **Token Security**: JTI-based tracking, IP/TabID validation, revocation via Kafka
- **Login Security**: Failed attempt tracking, single session enforcement
- **Maker-Checker Workflow**: For user creation/approval
- **Role-Based Access Control**: Complex organizational hierarchy support
- **Replay Attack Protection**: Nonce and timestamp validation

---

## 2. Architecture Design

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Angular 20 Frontend                      │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────┐   │
│  │ Auth Module  │  │  PKCE Flow   │  │  Encryption Module │   │
│  │  + DPoP      │  │  + DPoP Token│  │  (RSA-AES Hybrid)  │   │
│  └──────────────┘  └──────────────┘  └────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              ↕ HTTPS
┌─────────────────────────────────────────────────────────────────┐
│                         API Gateway (Optional)                   │
│                    Rate Limiting, WAF, Logging                   │
└─────────────────────────────────────────────────────────────────┘
                              ↕
        ┌────────────────────────────────────┐
        │                                    │
        ↓                                    ↓
┌──────────────────┐              ┌──────────────────────┐
│   Keycloak       │              │  Resource Server     │
│ (Auth Server)    │←────────────→│  (Spring Boot 3.x)   │
│                  │   JWKS/      │                      │
│ - OAuth 2.1      │   Introspect │ - REST APIs          │
│ - OIDC           │              │ - JWT Validation     │
│ - Custom SPIs    │              │ - Business Logic     │
└──────────────────┘              └──────────────────────┘
        ↓                                    ↓
┌──────────────────┐              ┌──────────────────────┐
│   Keycloak DB    │              │   Application DB     │
│   (PostgreSQL)   │              │   (PostgreSQL)       │
└──────────────────┘              └──────────────────────┘
                                           ↓
                              ┌──────────────────────┐
                              │   Apache Kafka       │
                              │ (Token Revocation)   │
                              └──────────────────────┘
        
┌──────────────────┐              ┌──────────────────────┐
│   LDAP/AD        │              │   External APIs      │
│ (Internal Users) │              │ - HRMS               │
│                  │              │ - Role Validation    │
│                  │              │ - SMS/Email Gateway  │
└──────────────────┘              └──────────────────────┘
```

### 2.2 Component Responsibilities

#### 2.2.1 Keycloak (Authorization Server)
- OAuth 2.1 / OIDC token issuance
- PKCE validation
- DPoP token binding
- LDAP federation for internal users
- Custom authenticators for CAPTCHA, OTP
- User federation for external users via custom SPI
- Session management

#### 2.2.2 Resource Server (Spring Boot)
- Business logic APIs
- JWT validation via JWKS
- Token revocation tracking (Caffeine cache)
- Request/Response encryption/decryption
- Replay attack prevention
- Maker-Checker workflow implementation
- Integration with external services (HRMS, SMS, Email)

#### 2.2.3 Angular Frontend
- PKCE authorization code flow
- DPoP proof generation
- RSA-AES hybrid encryption
- Token refresh handling
- Tab ID tracking
- CAPTCHA UI

---

## 3. Technology Stack

### 3.1 Backend Technologies

#### Authorization Server
```xml
<properties>
    <keycloak.version>24.0.1</keycloak.version>
</properties>

<!-- Keycloak runs standalone with custom SPIs -->
```

#### Resource Server (Spring Boot 3.x)
```xml
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>3.2.2</version>
</parent>

<properties>
    <java.version>21</java.version>
    <spring-cloud.version>2023.0.0</spring-cloud.version>
</properties>

<dependencies>
    <!-- Spring Boot -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>
    
    <!-- Spring LDAP -->
    <dependency>
        <groupId>org.springframework.ldap</groupId>
        <artifactId>spring-ldap-core</artifactId>
    </dependency>
    
    <!-- Caffeine Cache -->
    <dependency>
        <groupId>com.github.ben-manes.caffeine</groupId>
        <artifactId>caffeine</artifactId>
        <version>3.1.8</version>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-cache</artifactId>
    </dependency>
    
    <!-- Kafka -->
    <dependency>
        <groupId>org.springframework.kafka</groupId>
        <artifactId>spring-kafka</artifactId>
    </dependency>
    
    <!-- PostgreSQL -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
    </dependency>
    
    <!-- Nimbus JOSE JWT (for DPoP validation) -->
    <dependency>
        <groupId>com.nimbusds</groupId>
        <artifactId>nimbus-jose-jwt</artifactId>
        <version>9.37.3</version>
    </dependency>
    
    <!-- BouncyCastle for encryption -->
    <dependency>
        <groupId>org.bouncycastle</groupId>
        <artifactId>bcprov-jdk18on</artifactId>
        <version>1.77</version>
    </dependency>
    
    <!-- Apache POI for Excel -->
    <dependency>
        <groupId>org.apache.poi</groupId>
        <artifactId>poi-ooxml</artifactId>
        <version>5.2.5</version>
    </dependency>
    
    <!-- Lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
        <optional>true</optional>
    </dependency>
    
    <!-- MapStruct -->
    <dependency>
        <groupId>org.mapstruct</groupId>
        <artifactId>mapstruct</artifactId>
        <version>1.5.5.Final</version>
    </dependency>
</dependencies>
```

### 3.2 Frontend Technologies (Angular 20)
```json
{
  "dependencies": {
    "@angular/core": "^20.0.0",
    "@angular/common": "^20.0.0",
    "@angular/router": "^20.0.0",
    "@angular/forms": "^20.0.0",
    "angular-oauth2-oidc": "^17.0.0",
    "crypto-js": "^4.2.0",
    "jsrsasign": "^11.1.0",
    "uuid": "^9.0.1"
  }
}
```

---

## 4. Security Implementation

### 4.1 Hybrid RSA-AES Encryption

#### 4.1.1 Encryption Flow
```
Client → Server:
1. Generate random 256-bit AES key
2. Encrypt payload with AES-GCM
3. Encrypt AES key with server's RSA public key (2048-bit)
4. Send: {encryptedKey, encryptedData, iv, nonce, timestamp}

Server → Client:
1. Decrypt AES key using RSA private key
2. Decrypt payload using AES key
3. Encrypt response with same AES key
4. Send: {encryptedResponse, iv}
```

#### 4.1.2 Encryption Service Interface
```java
public interface EncryptionService {
    EncryptedRequest encryptRequest(Object payload, PublicKey publicKey);
    <T> T decryptRequest(EncryptedRequest request, Class<T> clazz);
    EncryptedResponse encryptResponse(Object payload, String aesKey);
    <T> T decryptResponse(EncryptedResponse response, String aesKey, Class<T> clazz);
}
```

### 4.2 Replay Attack Prevention

#### Components:
1. **Nonce**: UUID v4, stored in Caffeine cache (5-minute TTL)
2. **Timestamp**: Request timestamp, validated within 5-minute window
3. **Signature**: HMAC-SHA256 of (nonce + timestamp + payload)

#### Validation Logic:
```java
@Component
public class ReplayAttackValidator {
    
    @Cacheable(value = "nonces", key = "#nonce")
    public boolean validateNonce(String nonce) {
        // Returns false if nonce exists (replay attempt)
        return true;
    }
    
    public boolean validateTimestamp(long timestamp) {
        long currentTime = System.currentTimeMillis();
        return Math.abs(currentTime - timestamp) <= 300000; // 5 minutes
    }
}
```

### 4.3 DPoP (Demonstration of Proof of Possession)

#### DPoP Token Structure:
```json
{
  "typ": "dpop+jwt",
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "...",
    "e": "AQAB"
  }
}
{
  "jti": "unique-id",
  "htm": "POST",
  "htu": "https://resource-server.com/api/endpoint",
  "iat": 1234567890,
  "ath": "base64url(sha256(access_token))"
}
```

#### Validation:
```java
@Component
public class DPoPValidator {
    
    public boolean validateDPoPProof(String dpopProof, String accessToken, 
                                      HttpServletRequest request) {
        // 1. Parse and validate JWT
        // 2. Verify signature using JWK in header
        // 3. Validate htm matches HTTP method
        // 4. Validate htu matches request URL
        // 5. Validate ath matches access token hash
        // 6. Check jti uniqueness (replay protection)
        return true;
    }
}
```

### 4.4 Token Tracking & Revocation

#### Caffeine Cache Structure:
```java
@Configuration
public class CacheConfig {
    
    @Bean
    public Caffeine<Object, Object> caffeineConfig() {
        return Caffeine.newBuilder()
            .maximumSize(10000)
            .expireAfterWrite(30, TimeUnit.MINUTES);
    }
    
    @Bean
    public CacheManager cacheManager(Caffeine caffeine) {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager(
            "jwtMetadata", "captchas", "nonces", "blockedTokens"
        );
        cacheManager.setCaffeine(caffeine);
        return cacheManager;
    }
}
```

#### JWT Metadata Cache:
```java
@Data
public class JwtMetadata {
    private String jti;
    private String tabId;
    private String clientIp;
    private String subject;
    private TokenStatus status; // ACTIVE, REVOKED, BLOCKED
    private long expirationTime;
}
```

#### Kafka-based Token Revocation:
```java
// Producer (Auth Server or Resource Server)
@Service
public class TokenRevocationProducer {
    
    @Autowired
    private KafkaTemplate<String, TokenRevocationEvent> kafkaTemplate;
    
    public void revokeToken(String jti, String reason) {
        TokenRevocationEvent event = new TokenRevocationEvent(
            jti, reason, System.currentTimeMillis()
        );
        kafkaTemplate.send("token-revocation", jti, event);
    }
}

// Consumer (Resource Server)
@Service
public class TokenRevocationConsumer {
    
    @KafkaListener(topics = "token-revocation", groupId = "resource-server")
    public void handleRevocation(TokenRevocationEvent event) {
        cacheService.blockToken(event.getJti());
        log.info("Token revoked: {}, reason: {}", event.getJti(), event.getReason());
    }
}
```

### 4.5 CAPTCHA Implementation

#### Custom CAPTCHA Generator:
```java
@Service
public class CaptchaService {
    
    private static final String CAPTCHA_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final int CAPTCHA_LENGTH = 6;
    
    public CaptchaResponse generateCaptcha() {
        String captchaId = UUID.randomUUID().toString();
        String captchaText = generateRandomText();
        
        BufferedImage image = new BufferedImage(200, 60, BufferedImage.TYPE_INT_RGB);
        Graphics2D g2d = image.createGraphics();
        
        // Render with noise, distortion
        renderCaptcha(g2d, captchaText);
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "png", baos);
        String base64Image = Base64.getEncoder().encodeToString(baos.toByteArray());
        
        // Cache captcha text with 5-minute expiration
        cacheService.cacheCaptcha(captchaId, captchaText, 5, TimeUnit.MINUTES);
        
        return new CaptchaResponse(captchaId, base64Image);
    }
    
    public boolean validateCaptcha(String captchaId, String userInput) {
        String cachedText = cacheService.getCaptcha(captchaId);
        if (cachedText == null) return false;
        
        cacheService.invalidateCaptcha(captchaId);
        return cachedText.equalsIgnoreCase(userInput);
    }
}
```

### 4.6 Login Security

#### Failed Login Tracking:
```java
@Service
public class LoginSecurityService {
    
    private static final int MAX_FAILED_ATTEMPTS = 3;
    
    @Transactional
    public void recordFailedLogin(String username, String ipAddress) {
        LocalDate today = LocalDate.now();
        
        LoginAudit audit = auditRepository.findByUsernameAndDate(username, today)
            .orElse(new LoginAudit(username, today));
        
        audit.incrementFailedAttempts();
        
        if (audit.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
            audit.setAccountLocked(true);
            audit.setLockReason("Exceeded maximum failed login attempts");
            userService.lockUser(username);
        }
        
        auditRepository.save(audit);
    }
    
    @Scheduled(cron = "0 0 0 * * *") // Daily at midnight
    public void autoUnlockAccounts() {
        LocalDate yesterday = LocalDate.now().minusDays(1);
        List<LoginAudit> lockedAudits = auditRepository.findLockedAccountsBefore(yesterday);
        
        lockedAudits.forEach(audit -> {
            userService.unlockUser(audit.getUsername());
            audit.setAccountLocked(false);
            audit.setFailedAttempts(0);
        });
        
        auditRepository.saveAll(lockedAudits);
    }
}
```

#### Single Session Enforcement:
```java
@Component
public class SessionManagementFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                     HttpServletResponse response, 
                                     FilterChain chain) {
        String jti = extractJti(request);
        String tabId = request.getHeader("X-Tab-ID");
        String clientIp = getClientIp(request);
        
        JwtMetadata metadata = cacheService.getJwtMetadata(jti);
        
        if (metadata != null) {
            // Validate tab ID and IP
            if (!metadata.getTabId().equals(tabId) || 
                !metadata.getClientIp().equals(clientIp)) {
                
                // Suspicious activity - block token
                cacheService.blockToken(jti);
                kafkaProducer.revokeToken(jti, "Tab/IP mismatch");
                
                response.setStatus(HttpStatus.UNAUTHORIZED.value());
                return;
            }
        }
        
        chain.doFilter(request, response);
    }
}
```

---

## 5. Database Design

### 5.1 Core Tables

#### 5.1.1 Users Table
```sql
CREATE TABLE users (
    user_id BIGSERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    mobile VARCHAR(20),
    user_type VARCHAR(20) NOT NULL, -- INTERNAL, EXTERNAL
    password_hash VARCHAR(255), -- For external users only
    pf_id VARCHAR(50), -- For internal users
    branch_code VARCHAR(50),
    is_first_login BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT FALSE,
    is_locked BOOLEAN DEFAULT FALSE,
    created_by BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by BIGINT,
    updated_at TIMESTAMP,
    approved_by BIGINT,
    approved_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED
    CONSTRAINT fk_created_by FOREIGN KEY (created_by) REFERENCES users(user_id),
    CONSTRAINT fk_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id),
    CONSTRAINT fk_approved_by FOREIGN KEY (approved_by) REFERENCES users(user_id)
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_pf_id ON users(pf_id);
CREATE INDEX idx_users_status ON users(status);
```

#### 5.1.2 Roles Table
```sql
CREATE TABLE roles (
    role_id BIGSERIAL PRIMARY KEY,
    role_name VARCHAR(100) UNIQUE NOT NULL,
    role_code VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

INSERT INTO roles (role_name, role_code) VALUES
('Super Admin', 'SA'),
('Circle Admin', 'CA'),
('Maker', 'MAKER'),
('Checker', 'CHECKER'),
('Dashboard', 'DASHBOARD'),
('COD', 'COD'),
('CIT', 'CIT'),
('NCOD', 'NCOD'),
('CPC Authoriser', 'CPC_AUTHORISER'),
('SIO', 'SIO'),
('Advocate', 'ADVOCATE'),
('Valuer', 'VALUER'),
('Empanelled Vendors', 'EMP_VENDOR'),
('Empanelled Vendors Employees', 'EMP_VENDOR_EMP');
```

#### 5.1.3 User Roles Mapping
```sql
CREATE TABLE user_roles (
    user_role_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    assigned_by BIGINT,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_role FOREIGN KEY (role_id) REFERENCES roles(role_id),
    CONSTRAINT fk_assigned_by FOREIGN KEY (assigned_by) REFERENCES users(user_id),
    CONSTRAINT uk_user_role UNIQUE(user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
```

#### 5.1.4 Organizational Hierarchy Tables

```sql
-- Circle
CREATE TABLE circles (
    circle_id BIGSERIAL PRIMARY KEY,
    circle_code VARCHAR(50) UNIQUE NOT NULL,
    circle_name VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Network
CREATE TABLE networks (
    network_id BIGSERIAL PRIMARY KEY,
    network_code VARCHAR(50) UNIQUE NOT NULL,
    network_name VARCHAR(255) NOT NULL,
    circle_id BIGINT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_circle FOREIGN KEY (circle_id) REFERENCES circles(circle_id)
);

-- Module (AO)
CREATE TABLE modules (
    module_id BIGSERIAL PRIMARY KEY,
    module_code VARCHAR(50) UNIQUE NOT NULL,
    module_name VARCHAR(255) NOT NULL,
    network_id BIGINT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_network FOREIGN KEY (network_id) REFERENCES networks(network_id)
);

-- RBO/AGM Branch
CREATE TABLE rbo_branches (
    rbo_id BIGSERIAL PRIMARY KEY,
    rbo_code VARCHAR(50) UNIQUE NOT NULL,
    rbo_name VARCHAR(255) NOT NULL,
    module_id BIGINT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_module FOREIGN KEY (module_id) REFERENCES modules(module_id)
);

-- CM Branch
CREATE TABLE cm_branches (
    branch_id BIGSERIAL PRIMARY KEY,
    branch_code VARCHAR(50) UNIQUE NOT NULL,
    branch_name VARCHAR(255) NOT NULL,
    rbo_id BIGINT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_rbo FOREIGN KEY (rbo_id) REFERENCES rbo_branches(rbo_id)
);

-- CPC
CREATE TABLE cpcs (
    cpc_id BIGSERIAL PRIMARY KEY,
    cpc_code VARCHAR(50) UNIQUE NOT NULL,
    cpc_name VARCHAR(255) NOT NULL,
    branch_id BIGINT NOT NULL,
    cpc_category VARCHAR(20), -- AGR, PPBU, REHBU, SME
    is_nodal BOOLEAN DEFAULT FALSE,
    bpr_center_id BIGINT,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_branch FOREIGN KEY (branch_id) REFERENCES cm_branches(branch_id),
    CONSTRAINT fk_bpr_center FOREIGN KEY (bpr_center_id) REFERENCES bpr_centers(bpr_center_id)
);

-- State
CREATE TABLE states (
    state_id BIGSERIAL PRIMARY KEY,
    state_code VARCHAR(10) UNIQUE NOT NULL,
    state_name VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- District
CREATE TABLE districts (
    district_id BIGSERIAL PRIMARY KEY,
    district_code VARCHAR(20) UNIQUE NOT NULL,
    district_name VARCHAR(100) NOT NULL,
    state_id BIGINT NOT NULL,
    bpr_center_id BIGINT,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_state FOREIGN KEY (state_id) REFERENCES states(state_id),
    CONSTRAINT fk_bpr_center FOREIGN KEY (bpr_center_id) REFERENCES bpr_centers(bpr_center_id)
);

-- BPR Center
CREATE TABLE bpr_centers (
    bpr_center_id BIGSERIAL PRIMARY KEY,
    bpr_center_code VARCHAR(50) UNIQUE NOT NULL,
    bpr_center_name VARCHAR(255) NOT NULL,
    district_id BIGINT NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_district FOREIGN KEY (district_id) REFERENCES districts(district_id)
);
```

#### 5.1.5 User Location Mapping

```sql
-- User to CPC mapping (One-to-One for COD, NCOD, CIT, CPC Head)
CREATE TABLE user_cpc_mapping (
    mapping_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    cpc_id BIGINT NOT NULL,
    is_primary BOOLEAN DEFAULT TRUE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_cpc FOREIGN KEY (cpc_id) REFERENCES cpcs(cpc_id)
);

-- User to BPR mapping (Many-to-One for SIO)
CREATE TABLE user_bpr_mapping (
    mapping_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    bpr_center_id BIGINT NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_bpr FOREIGN KEY (bpr_center_id) REFERENCES bpr_centers(bpr_center_id),
    CONSTRAINT uk_user_bpr UNIQUE(user_id, bpr_center_id)
);

-- Empanelled Vendors
CREATE TABLE empanelled_vendors (
    vendor_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT UNIQUE NOT NULL,
    vendor_name VARCHAR(255) NOT NULL,
    vendor_type VARCHAR(50), -- ADVOCATE, VALUER, etc.
    registration_number VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Vendor to CPC mapping (Many-to-Many)
CREATE TABLE vendor_cpc_mapping (
    mapping_id BIGSERIAL PRIMARY KEY,
    vendor_id BIGINT NOT NULL,
    cpc_id BIGINT NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_vendor FOREIGN KEY (vendor_id) REFERENCES empanelled_vendors(vendor_id),
    CONSTRAINT fk_cpc FOREIGN KEY (cpc_id) REFERENCES cpcs(cpc_id),
    CONSTRAINT uk_vendor_cpc UNIQUE(vendor_id, cpc_id)
);

-- Vendor Employees
CREATE TABLE vendor_employees (
    employee_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT UNIQUE NOT NULL,
    vendor_id BIGINT NOT NULL,
    employee_code VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT fk_vendor FOREIGN KEY (vendor_id) REFERENCES empanelled_vendors(vendor_id)
);
```

#### 5.1.6 Audit & Security Tables

```sql
-- Login Audit
CREATE TABLE login_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT,
    username VARCHAR(100) NOT NULL,
    login_date DATE NOT NULL,
    failed_attempts INT DEFAULT 0,
    successful_login_time TIMESTAMP,
    last_failed_time TIMESTAMP,
    ip_address VARCHAR(50),
    user_agent TEXT,
    is_account_locked BOOLEAN DEFAULT FALSE,
    lock_reason VARCHAR(255),
    unlocked_by BIGINT,
    unlocked_at TIMESTAMP,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id),
    CONSTRAINT uk_user_date UNIQUE(username, login_date)
);

-- Token Audit
CREATE TABLE token_audit (
    token_audit_id BIGSERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL,
    user_id BIGINT,
    tab_id VARCHAR(255),
    client_ip VARCHAR(50),
    issued_at TIMESTAMP,
    expires_at TIMESTAMP,
    token_status VARCHAR(20), -- ACTIVE, REVOKED, BLOCKED, EXPIRED
    revoked_at TIMESTAMP,
    revoke_reason VARCHAR(255),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE INDEX idx_token_audit_jti ON token_audit(jti);
CREATE INDEX idx_token_audit_user ON token_audit(user_id);
CREATE INDEX idx_token_audit_status ON token_audit(token_status);

-- API Access Audit
CREATE TABLE api_audit (
    api_audit_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT,
    jti VARCHAR(255),
    http_method VARCHAR(10),
    endpoint VARCHAR(500),
    request_timestamp TIMESTAMP,
    response_status INT,
    response_time_ms BIGINT,
    client_ip VARCHAR(50),
    tab_id VARCHAR(255),
    error_message TEXT,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE INDEX idx_api_audit_user ON api_audit(user_id);
CREATE INDEX idx_api_audit_timestamp ON api_audit(request_timestamp);
```

#### 5.1.7 Maker-Checker Tables

```sql
-- Pending User Approvals
CREATE TABLE pending_approvals (
    approval_id BIGSERIAL PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL, -- USER, ROLE, MAPPING
    entity_id BIGINT NOT NULL,
    action_type VARCHAR(20) NOT NULL, -- CREATE, UPDATE, DELETE
    maker_id BIGINT NOT NULL,
    checker_id BIGINT,
    approval_status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, APPROVED, REJECTED
    maker_comments TEXT,
    checker_comments TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP,
    old_data JSONB,
    new_data JSONB,
    CONSTRAINT fk_maker FOREIGN KEY (maker_id) REFERENCES users(user_id),
    CONSTRAINT fk_checker FOREIGN KEY (checker_id) REFERENCES users(user_id)
);

CREATE INDEX idx_pending_approvals_status ON pending_approvals(approval_status);
CREATE INDEX idx_pending_approvals_maker ON pending_approvals(maker_id);
```

#### 5.1.8 OTP Table

```sql
CREATE TABLE otp_records (
    otp_id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    otp_code VARCHAR(10) NOT NULL,
    otp_type VARCHAR(20) NOT NULL, -- LOGIN, PASSWORD_RESET
    delivery_method VARCHAR(10) NOT NULL, -- EMAIL, SMS
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP,
    attempts INT DEFAULT 0,
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE INDEX idx_otp_user ON otp_records(user_id);
CREATE INDEX idx_otp_expiry ON otp_records(expires_at);
```

---

## 6. Authentication Flows

### 6.1 Internal User Login (LDAP)

```
┌────────┐                ┌─────────┐              ┌──────────┐              ┌──────────┐
│ Client │                │Keycloak │              │   LDAP   │              │Resource  │
│        │                │         │              │          │              │ Server   │
└───┬────┘                └────┬────┘              └────┬─────┘              └────┬─────┘
    │                          │                        │                         │
    │ 1. GET /captcha          │                        │                         │
    │────────────────────────> │                        │                         │
    │                          │                        │                         │
    │ 2. captchaId, image      │                        │                         │
    │ <──────────────────────  │                        │                         │
    │                          │                        │                         │
    │ 3. PKCE: code_challenge  │                        │                         │
    │    /authorize            │                        │                         │
    │────────────────────────> │                        │                         │
    │                          │                        │                         │
    │ 4. Login page            │                        │                         │
    │ <──────────────────────  │                        │                         │
    │                          │                        │                         │
    │ 5. POST /authenticate    │                        │                         │
    │    {username, password,  │                        │                         │
    │     captchaId, captcha}  │                        │                         │
    │────────────────────────> │                        │                         │
    │                          │                        │                         │
    │                          │ 6. Validate CAPTCHA    │                         │
    │                          │────────────────────────┼────────────────────────>│
    │                          │                        │                         │
    │                          │ 7. Authenticate via    │                         │
    │                          │    LDAP                │                         │
    │                          │──────────────────────> │                         │
    │                          │                        │                         │
    │                          │ 8. User details        │                         │
    │                          │ <───────────────────── │                         │
    │                          │                        │                         │
    │                          │ 9. Check login attempts│                         │
    │                          │────────────────────────┼────────────────────────>│
    │                          │                        │                         │
    │                          │ 10. Validate session   │                         │
    │                          │     (single session)   │                         │
    │                          │────────────────────────┼────────────────────────>│
    │                          │                        │                         │
    │ 11. Authorization code   │                        │                         │
    │ <──────────────────────  │                        │                         │
    │                          │                        │                         │
    │ 12. POST /token          │                        │                         │
    │     {code, code_verifier,│                        │                         │
    │      DPoP proof}         │                        │                         │
    │────────────────────────> │                        │                         │
    │                          │                        │                         │
    │                          │ 13. Validate PKCE      │                         │
    │                          │     Validate DPoP      │                         │
    │                          │                        │                         │
    │ 14. Access token,        │                        │                         │
    │     Refresh token,       │                        │                         │
    │     ID token             │                        │                         │
    │ <──────────────────────  │                        │                         │
    │                          │                        │                         │
    │ 15. Store token metadata │                        │                         │
    │     (jti, tabId, IP)     │                        │                         │
    │────────────────────────────────────────────────────┼────────────────────────>│
```

### 6.2 External User Login (Username/Password + OTP)

```
Additional steps after CAPTCHA validation:

1. Keycloak custom authenticator sends OTP via Resource Server API
2. User receives OTP (email/SMS)
3. User submits OTP
4. Keycloak validates OTP (calls Resource Server)
5. If first login, force password reset
6. Continue with PKCE flow
```

### 6.3 API Request Flow with Encryption

```
┌────────┐                                             ┌──────────┐
│ Client │                                             │ Resource │
│        │                                             │ Server   │
└───┬────┘                                             └────┬─────┘
    │                                                       │
    │ 1. Generate AES-256 key                              │
    │                                                       │
    │ 2. Encrypt payload with AES-GCM                      │
    │                                                       │
    │ 3. Encrypt AES key with RSA public key              │
    │                                                       │
    │ 4. Generate nonce, timestamp                         │
    │                                                       │
    │ 5. POST /api/endpoint                                │
    │    Headers:                                           │
    │      Authorization: DPoP <access_token>              │
    │      DPoP: <dpop_proof>                              │
    │      X-Tab-ID: <tab_id>                              │
    │    Body:                                              │
    │      {encryptedKey, encryptedData,                   │
    │       iv, nonce, timestamp}                          │
    │─────────────────────────────────────────────────────>│
    │                                                       │
    │                                   6. Validate JWT    │
    │                                      - Signature via │
    │                                        JWKS          │
    │                                      - Expiry        │
    │                                      - Claims        │
    │                                                       │
    │                                   7. Validate DPoP   │
    │                                      - JWK signature │
    │                                      - htm, htu      │
    │                                      - ath hash      │
    │                                                       │
    │                                   8. Check cache     │
    │                                      - JTI metadata  │
    │                                      - Tab ID match  │
    │                                      - IP match      │
    │                                      - Token status  │
    │                                                       │
    │                                   9. Validate replay │
    │                                      - Nonce unique  │
    │                                      - Timestamp OK  │
    │                                                       │
    │                                   10. Decrypt request│
    │                                       - RSA private  │
    │                                       - AES-GCM      │
    │                                                       │
    │                                   11. Process request│
    │                                                       │
    │                                   12. Encrypt response│
    │                                       - Same AES key│
    │                                                       │
    │ 13. {encryptedResponse, iv}                          │
    │ <───────────────────────────────────────────────────│
    │                                                       │
    │ 14. Decrypt with stored AES key                      │
```

---

## 7. API Specifications

### 7.1 Authentication APIs (Keycloak)

#### 7.1.1 Generate CAPTCHA
```
GET /auth/realms/{realm}/captcha

Response:
{
  "captchaId": "uuid",
  "captchaImage": "data:image/png;base64,..."
}
```

#### 7.1.2 Authorization Endpoint (PKCE)
```
GET /auth/realms/{realm}/protocol/openid-connect/auth
  ?client_id=angular-client
  &response_type=code
  &redirect_uri=http://localhost:4200/callback
  &scope=openid profile email
  &code_challenge=<base64url(sha256(code_verifier))>
  &code_challenge_method=S256
  &state=<random_state>
```

#### 7.1.3 Token Endpoint
```
POST /auth/realms/{realm}/protocol/openid-connect/token
Headers:
  DPoP: <dpop_proof_jwt>
  Content-Type: application/x-www-form-urlencoded

Body:
  grant_type=authorization_code
  &code=<authorization_code>
  &redirect_uri=http://localhost:4200/callback
  &client_id=angular-client
  &code_verifier=<code_verifier>

Response:
{
  "access_token": "...",
  "token_type": "DPoP",
  "refresh_token": "...",
  "expires_in": 1800,
  "refresh_expires_in": 3600,
  "id_token": "..."
}
```

#### 7.1.4 Token Refresh
```
POST /auth/realms/{realm}/protocol/openid-connect/token
Headers:
  DPoP: <new_dpop_proof>

Body:
  grant_type=refresh_token
  &refresh_token=<refresh_token>
  &client_id=angular-client

Response: (same as token endpoint)
```

#### 7.1.5 Logout
```
POST /auth/realms/{realm}/protocol/openid-connect/logout
Body:
  refresh_token=<refresh_token>
  &client_id=angular-client
```

### 7.2 Resource Server APIs

#### 7.2.1 User Management APIs

##### Create User (Maker)
```
POST /api/v1/users
Headers:
  Authorization: DPoP <access_token>
  DPoP: <dpop_proof>
  X-Tab-ID: <tab_id>
  Content-Type: application/json

Request Body (Encrypted):
{
  "encryptedKey": "<rsa_encrypted_aes_key>",
  "encryptedData": "<aes_encrypted_payload>",
  "iv": "<initialization_vector>",
  "nonce": "<uuid>",
  "timestamp": 1234567890000
}

Decrypted Payload:
{
  "userType": "INTERNAL|EXTERNAL",
  "username": "string",
  "email": "string",
  "mobile": "string",
  "pfId": "string", // For internal
  "roles": ["ROLE_CODE"],
  "cpcMappings": [1, 2, 3],
  "bprMappings": [1],
  "makerComments": "string"
}

Response (Encrypted):
{
  "encryptedResponse": "<aes_encrypted_response>",
  "iv": "<initialization_vector>"
}

Decrypted Response:
{
  "userId": 123,
  "username": "string",
  "status": "PENDING_APPROVAL",
  "approvalId": 456
}
```

##### Approve User (Checker)
```
POST /api/v1/users/approvals/{approvalId}/approve
Headers:
  Authorization: DPoP <access_token>
  DPoP: <dpop_proof>
  X-Tab-ID: <tab_id>

Request Body (Encrypted):
{
  "checkerComments": "Approved"
}

Response:
{
  "userId": 123,
  "username": "string",
  "status": "APPROVED",
  "approvedAt": "2024-01-15T10:30:00Z"
}
```

##### Bulk User Creation (Excel Upload)
```
POST /api/v1/users/bulk-upload
Headers:
  Authorization: DPoP <access_token>
  DPoP: <dpop_proof>
  X-Tab-ID: <tab_id>
  Content-Type: multipart/form-data

Form Data:
  file: <excel_file>
  userType: EXTERNAL
  roleCode: COD

Response:
{
  "totalRecords": 100,
  "successCount": 95,
  "failureCount": 5,
  "errors": [
    {
      "row": 10,
      "error": "Invalid email format"
    }
  ]
}
```

#### 7.2.2 Role Validation API
```
GET /api/v1/users/{userId}/validate-role
Headers:
  Authorization: DPoP <access_token>
  DPoP: <dpop_proof>
  X-Tab-ID: <tab_id>

Query Params:
  roleCode: COD|CPC_HEAD

Response:
{
  "valid": true,
  "validationDetails": {
    "branchMatch": true,
    "esgCode": "3",
    "egCode": "J"
  }
}
```

#### 7.2.3 Token Management APIs

##### Store Token Metadata
```
POST /api/v1/tokens/metadata
Headers:
  Authorization: DPoP <access_token>
  X-Tab-ID: <tab_id>

Request Body:
{
  "jti": "string",
  "tabId": "string",
  "clientIp": "string"
}

Response:
{
  "success": true
}
```

##### Revoke Token
```
POST /api/v1/tokens/revoke
Headers:
  Authorization: DPoP <access_token>
  X-Tab-ID: <tab_id>

Request Body (Encrypted):
{
  "reason": "User logout"
}

Response:
{
  "revoked": true,
  "revokedAt": "2024-01-15T10:30:00Z"
}
```

---

## 8. Code Implementation

### 8.1 Keycloak Configuration

#### 8.1.1 Custom Authenticator for CAPTCHA

```java
package com.organization.keycloak.authenticator;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class CaptchaAuthenticator implements Authenticator {

    private static final String CAPTCHA_FORM = "captcha-form.ftl";
    
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challenge = context.form()
            .createForm(CAPTCHA_FORM);
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String captchaId = formData.getFirst("captchaId");
        String captchaInput = formData.getFirst("captchaInput");
        
        // Call Resource Server to validate CAPTCHA
        boolean valid = validateCaptcha(context.getSession(), captchaId, captchaInput);
        
        if (valid) {
            context.success();
        } else {
            Response challenge = context.form()
                .setError("invalidCaptcha")
                .createForm(CAPTCHA_FORM);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        }
    }
    
    private boolean validateCaptcha(KeycloakSession session, String captchaId, String captchaInput) {
        // HTTP client call to resource server
        // GET /api/v1/captcha/validate?captchaId={captchaId}&input={captchaInput}
        return true; // Placeholder
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession




/////////////////////////








Technical Design Document: Scalable OAuth 2.1 Authentication and Resource ServerSection I: System Architecture BlueprintThis document outlines the technical design for a secure, scalable, and production-grade authentication, authorization, and resource server system. The architecture is designed to meet complex business requirements, including multi-factor authentication, hybrid payload encryption, distributed session management, and complex hierarchical data modeling.1.1. High-Level System Diagram (C4 Container Model)The system architecture adheres to a C4 Container model, providing a clear boundary and interaction map for all major components.1 The system is composed of three primary containers and five key external systems.Containers:Angular SPA (Client): A single-page application built on Angular 20. This is the primary user interface, running entirely within the end-user's web browser.3Spring Boot API (Resource Server): The backend application built on Spring Boot 3.x and Java 21. It serves the RESTful API, executes all business logic, manages the database, and enforces authorization rules.4Keycloak (Authorization Server): A dedicated, standalone server responsible for all identity and access management (IAM). It handles user authentication, identity federation, and the issuance of OIDC/OAuth 2.1 tokens.5External Systems:Application Database: A relational database (e.g., PostgreSQL) that stores all business data, external user identities, role mappings, location hierarchies, and audit logs.Microsoft Active Directory (LDAP): The external corporate identity provider (IdP) for all internal users.6HRMS API: An external REST API used to fetch and validate data for internal users (e.g., PF ID, Branch).7Role Validation API: An external REST API used for conditional, dynamic authorization checks for specific user roles.Kafka Cluster: An asynchronous event bus used for distributed state synchronization, primarily for token revocation and cache invalidation.Key Interaction Flows:Authentication: The Angular SPA initiates the OIDC Authorization Code Flow with PKCE, redirecting the user to Keycloak. Keycloak authenticates the user (via LDAP, its internal database, or custom SPIs) and redirects back with an authorization code. The SPA exchanges this code (along with a DPoP proof) for a set of tokens.8API Request: The Angular SPA makes a request to the Spring Boot Resource Server, attaching a DPoP-bound access token 9 and a custom-encrypted payload.10Token Validation: The Spring Boot server validates the access token's signature by fetching the public keys from Keycloak's JWKS endpoint.11 It then performs a separate, mandatory validation of the DPoP proof.12User Federation: Keycloak synchronizes with Active Directory via LDAP for internal users 13 and uses a custom Service Provider Interface (SPI) to delegate authentication for external users to the Spring Boot application.14External Data Validation: The Spring Boot server communicates with the HRMS API and Role Validation API via RESTful WebClient calls to enrich or validate business logic.151.2. Project Structuring Strategy: A Unified MonorepoThe system comprises three distinct but tightly coupled projects: the Angular frontend, the Spring Boot backend, and the Java-based Keycloak SPIs. Managing these in separate repositories (a multi-repo approach 16) introduces significant operational friction, particularly around shared data transfer objects (DTOs), API contract versioning, and coordinated, atomic commits.A Monorepo strategy is the recommended solution to manage this complexity.18 This approach unifies all projects into a single Git repository, streamlining dependency management and enabling a more cohesive CI/CD pipeline.The Nx build system 19 will be leveraged to manage the monorepo. Nx provides first-class, integrated support for both Angular 19 and Spring Boot (via dedicated Gradle/Maven plugins 20). Its primary advantages include:Intelligent Task Running: Nx builds a dependency graph of the projects.Affected Commands: Commands like nx affected:test will only run tests for projects that were actually impacted by a code change, dramatically speeding up CI cycles.16Simplified Code Sharing: Enables seamless sharing of code, such as TypeScript interfaces for DTOs that can be used by both the Angular client and (with minor translation) the Spring backend.The recommended monorepo structure is as follows:/my-app-monorepo/

|-- /apps/
| |-- /angular-client/       (Angular 20 Application) 
| |-- /spring-resource-server/ (Spring Boot 3 Application) 
|-- /libs/
| |-- /keycloak-spis/        (Java project for custom Keycloak SPIs) [22]
| |-- /shared-dtos/          (TypeScript interfaces for API contracts)
|-- nx.json
|-- package.json               (Frontend/Nx dependencies)
|-- pom.xml                    (Root Maven POM for backend projects)
1.3. Backend Architecture: Multi-Module Clean ArchitectureTo satisfy the "Clean Architecture" requirement, the Spring Boot Resource Server will be structured as a multi-module Maven project.23 This design physically enforces the Dependency Rule: all dependencies must point inwards, from technology-specific details to abstract business logic.27This structure ensures the core business logic is decoupled from frameworks (like Spring) and external details (like databases or APIs), making it independently testable, portable, and maintainable.29 The automated testing pipeline will use ArchUnit 21 to programmatically enforce these architectural boundaries and fail any build that violates the Dependency Rule.The Maven modules will be structured as follows 30:app-domain: The innermost core of the application. It contains only pure Java 21 code.Contents: JPA entities, value objects, domain events, and interfaces for repositories and use cases.Dependencies: None (except Java base libraries). It has zero knowledge of Spring, Kafka, or any database.app-application: The orchestration layer that implements the core business logic.Contents: Use case implementations (e.g., services like UserOnboardingService).Dependencies: app-domain only.app-infrastructure: The outermost layer, containing all technology-specific implementations.Contents: Spring Data JPA repository implementations, Kafka publishers and listeners 33, WebClient API clients 15, and Keycloak Admin API clients. It implements the interfaces defined in the app-domain and app-application layers.Dependencies: app-application, app-domain, Spring Boot, Spring Data, Kafka Client.app-bootstrap: The executable entry point of the application.Contents: The main @SpringBootApplication class, application.yml, and Spring @Configuration classes to wire all modules together using Dependency Injection.Dependencies: All other modules.1.4. Frontend Architecture: Layered Feature DesignThe Angular 20 application will mirror the Clean Architecture principles of the backend to ensure scalability and separation of concerns.34 The architecture will leverage modern Angular 20 features, including standalone components and APIs, to reduce boilerplate and simplify dependency management.37The project folder structure will be organized by architectural layer 34:src/app/core: Contains global, application-wide concerns. This module is instantiated once.Contents: The main HttpInterceptor (for DPoP and Encryption), the AuthService (managing OIDC), route guards, and global configuration providers.src/app/domain: Defines the core business logic and models of the application.Contents: TypeScript interfaces and models (e.g., User.model.ts, CPC.model.ts) and the NgRx state management definitions (actions, reducers, selectors, and effects).39src/app/infrastructure: The data access layer.Contents: Angular services (e.g., UserDataService, LocationDataService) that abstract all HTTP calls to the Spring Boot backend. These services implement repository interfaces defined in the domain layer.src/app/features: The UI layer, broken down by business capability.Contents: Each feature (e.g., user-management, dashboard) contains its own set of components, containers (smart components), and optional facades (which provide a simple BLoC-style API 34 to components for complex state interactions).Section II: Authorization Server (Keycloak) Configuration and CustomizationThe system's requirements for authentication go far beyond Keycloak's standard capabilities. A suite of custom Service Provider Interfaces (SPIs) is required to meet the demands for a custom CAPTCHA, granular login blocking, and conditional session logic.2.1. Realm and Client ConfigurationA new realm (e.g., my-app-realm) will be created to isolate this application's configuration. Within this realm, a new OIDC client (e.g., angular-client) will be configured with the following critical settings:Client Authentication: Off. The Angular application is a public client and cannot securely store a secret.Authorization: On.Authentication Flow: Standard Flow (which implements the OAuth 2.0 Authorization Code Flow 8).Proof Key for Code Exchange (PKCE): Enabled. This is a mandatory security measure for OAuth 2.1 public clients.40 The Code Challenge Method will be set to S256.41Demonstrating Proof of Possession (DPoP): Enabled. This configures Keycloak to issue sender-constrained access tokens and validate DPoP proofs during the token exchange, as per the OAuth 2.1 best practices.43Valid Redirect URIs: Configured to the Angular application's callback URL (e.g., http://localhost:4200/*).2.2. User Federation StrategyThe system must support two distinct user types with different identity stores.Internal Users: These users will be federated from the corporate Microsoft Active Directory. Keycloak's built-in "User Federation" 44 will be configured as follows:Provider: ldap.6Vendor: Active Directory.13Edit Mode: READ_ONLY.13 All user management for internal users is handled by the corporate IT team via AD.External Users: These users are managed by the application and stored in the primary Application Database. To authenticate them, Keycloak must be taught how to find and validate them. This will be achieved by implementing a custom UserStorageProvider SPI.14Design Pattern: The SPI will follow a delegation model. Instead of connecting to the database directly (which would tightly couple Keycloak to the application's schema), the SPI will make internal REST API calls to the Spring Boot application.Implementation: A custom Java JAR will be deployed to Keycloak's /providers directory.49UserLookupProvider.getUserByUsername(String username): This method will use a java.net.http.HttpClient to call a firewalled, internal-only endpoint on the Spring Boot server (e.g., GET /api/internal/users/lookup/{username}).CredentialValidation.isValid(RealmModel realm, UserModel user, CredentialInput input): This method will delegate password validation by calling another internal endpoint (e.g., POST /api/internal/users/validate-password).This design elegantly consolidates all user management logic (for external users) within the Spring Boot application, treating Keycloak as a pass-through authentication gateway.2.3. Custom Authentication Flow OrchestrationA single, unified authentication flow is required to orchestrate all security policies. A new "Basic" flow will be created in Keycloak and bound as the realm's "Browser Flow".14This flow will execute the following steps in order:Custom CAPTCHA Authenticator (REQUIRED): A custom SPI to present and validate the internally-generated CAPTCHA. (See Section 2.4).Username Password Form (REQUIRED): The built-in form for collecting credentials.Custom Brute Force Listener (REQUIRED): A custom SPI to audit login failures. (See Section 2.5).Custom User Type Router (REQUIRED): A new custom SPI (authenticator) that inspects the username format (e.g., numeric PF ID vs. email) and directs the flow to the correct sub-flow.Conditional Sub-Flow: Internal (ALTERNATIVE): This flow executes if the user is identified as Internal.User Federation (LDAP) (REQUIRED): The built-in execution that validates credentials against Active Directory.Conditional Sub-Flow: External (ALTERNATIVE): This flow executes if the user is identified as External.Custom User Storage Provider (REQUIRED): The SPI that delegates validation to the Spring Boot API. (See Section 2.2).Custom OTP Authenticator (REQUIRED): A new custom SPI 44 that generates an OTP, calls the Spring Boot API (which in turn uses an internal service to send the email/SMS), and presents an OTP entry form to the user.Custom Single Session Consenter (REQUIRED): A custom SPI to enforce the "one active session" policy with user consent. (See Section 2.6).Check First-Time Login (CONDITIONAL): This step checks for the "Update Password" required action and forces a password reset if present. (See Section 2.7).2.4. SPI: Custom CAPTCHA ImplementationThe requirement for an internally generated CAPTCHA 14 (not reCAPTCHA) that uses Caffeine for caching necessitates a fully custom SPI. This presents a technical challenge, as Keycloak's native caching is Infinispan.50 The solution is to embed the Caffeine library 51 directly into the custom SPI's JAR file.The implementation will be a custom Authenticator SPI 22:Factory: The CustomCaptchaFactory will initialize a static Cache<String, String> captchaCache = Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).build(); to store CAPTCHA answers.authenticate(AuthenticationFlowContext context) (Page Load):A captchaId (UUID) and captchaAnswer (e.g., 6 random alphanumeric characters) are generated.java.awt.Graphics2D 52 is used to draw the captchaAnswer text onto a BufferedImage, along with distortion lines and noise to deter bots.54The BufferedImage is converted to a Base64 string:JavaByteArrayOutputStream os = new ByteArrayOutputStream();
ImageIO.write(image, "png", os);
String base64Image = Base64.getEncoder().encodeToString(os.toByteArray());
The answer is stored in the cache: captchaCache.put(captchaId, captchaAnswer);.The captchaId and base64Image are passed to the custom login template (custom-login.ftl) via context.form().setAttribute(...).action(AuthenticationFlowContext context) (Form Submit):The user's response and the captchaId are retrieved from the context.getHttpRequest().getDecodedFormParameters().The expected answer is retrieved: String expectedAnswer = captchaCache.getIfPresent(captchaId);.If the expectedAnswer is valid and matches the user's input, context.success() is called.Otherwise, the flow is failed with context.failure(AuthenticationFlowError.INVALID_CREDENTIALS).2.5. SPI: Brute Force Login BlockingA hybrid approach is required to meet the specific blocking and auditing requirements.Keycloak Configuration: The built-in "Brute Force Detection" 55 will be enabled with a high failure threshold (e.g., Max Login Failures: 10) to act as a temporary safety net.SPI Implementation (AuditLoginListenerProvider): A custom EventListenerProvider SPI 58 will be implemented.The onEvent(Event event) method will listen for EventType.LOGIN_ERROR.On a LOGIN_ERROR event, the SPI will use a Java HttpClient to make an asynchronous, non-blocking call to a secure endpoint on the Spring Boot server: POST /api/internal/audit/login-failure, sending the event.getUserId() and event.getIpAddress().Spring Boot Logic:The /api/internal/audit/login-failure endpoint will record the failure in an AUDIT_LOGIN_FAILURES table.A service will check the count: SELECT COUNT(*) FROM AUDIT_LOGIN_FAILURES WHERE user_id =? AND timestamp >= [start_of_day].If the count >= 3, the service will use the Keycloak Admin API client to fetch the UserRepresentation and update it: user.setEnabled(false). This persistently locks the account for the day.Unblocking Mechanisms:Admin Unblock: A new UI will be created in the Angular application for users with the "CA" (Circle Admin) role. This UI will list locked users and provide an "Unblock" button, which calls a Spring Boot API to re-enable the user via the Keycloak Admin API.Auto-Unblock: A Spring Boot @Scheduled job will run at midnight ("0 0 0 * * *") to find all users blocked by this mechanism, re-enable them, and purge old entries from the AUDIT_LOGIN_FAILURES table.2.6. SPI: Single Session PolicyThe requirement to "Allow only one active session... with user consent" cannot be met by the built-in "User Session Count Limiter" 61, as that feature can only deny new sessions or terminate old ones without user interaction.44 A custom Authenticator SPI is required.Implementation (SingleSessionConsenter SPI):This SPI 49 will be added to the custom authentication flow (Section 2.3) after successful credential validation.authenticate(AuthenticationFlowContext context):The authenticated user is retrieved: UserModel user = context.getUser();.Active sessions are checked: List<UserSessionModel> sessions = context.getSession().userSessions().getUserSessions(realm, user);.If sessions.isEmpty(), the user has no other sessions, and context.success() is called.If sessions exist, the user is challenged with a custom consent form: context.form().createForm("custom-consent-logout.ftl");. This form will present two options: "Log out other sessions and continue" or "Cancel new login."action(AuthenticationFlowContext context):The user's choice is retrieved from the form parameters.If "logout_others": The SPI iterates through the sessions list and calls context.getSession().sessions().removeUserSession(realm, s) for each one 64, invalidating them. context.success() is then called.If "cancel": The new login is aborted by calling context.failure(AuthenticationFlowError.SESSION_LIMIT_EXCEEDED).2.7. SPI: First-Time Password ResetThis requirement for external users does not require a custom SPI. It can be fulfilled by properly using the Keycloak Admin REST API during the Maker-Checker user creation workflow (detailed in Section V.1).When the "Checker" approves a new external user, the Spring Boot service will provision the account in Keycloak by calling POST /admin/realms/{realm}/users.65 The UserRepresentation JSON payload will be specifically constructed to set a temporary password and trigger the built-in "Update Password" required action 14:JSON{
  "username": "new.external.user@email.com",
  "enabled": true,
  "credentials":,
  "requiredActions":
}
This configuration forces Keycloak to direct the user to the password reset screen immediately after their first successful login with the temporary password.Section III: Resource Server (Spring Boot) Security ArchitectureThe Spring Boot application acts as the OAuth 2.1 Resource Server. It must be configured to validate DPoP-bound tokens, handle custom encryption, and manage a distributed token blocklist.3.1. OAuth 2.1 and JWT ValidationThe spring-boot-starter-oauth2-resource-server dependency 68 will be the foundation of the security configuration. The application.yml will be configured with the Keycloak realm's issuer URI:YAMLspring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080/realms/my-app-realm
This single property enables Spring Security's auto-configuration.70 Spring will use this URI to discover Keycloak's .well-known/openid-configuration endpoint, find the jwks_uri, and automatically configure a NimbusJwtDecoder.11 This decoder validates the token's cryptographic signature (against Keycloak's public keys 71), the iss (issuer) claim, and the exp (expiration) claim on every incoming request.723.2. DPoP Proof Validation (Sender-Constrained Tokens)Standard JWT validation is insufficient for DPoP-bound tokens.73 DPoP, a core component of OAuth 2.1 40, requires the server to validate that the client possesses the private key corresponding to the public key bound to the access token. This binding is represented by the cnf.jkt claim in the access token.73A custom AuthenticationProvider 43 must be implemented to replace the default JWT processing.Implementation (DpopAuthenticationProvider): This provider will be registered in the SecurityFilterChain.Extraction: It will extract the Authorization header (e.g., DPoP <access_token>) and the DPoP header (the DPoP proof JWT) from the HttpServletRequest.73Step-by-Step Validation Logic: The provider must execute the following validation chain for every request, as specified in RFC 9449 and related guides 12:a. Parse Access Token: Use the default JwtDecoder to parse and validate the access token. Extract its claims.b. Check for cnf Claim: Retrieve the cnf (confirmation) claim and its nested jkt (JSON Web Key Thumbprint) value.73 If this claim is absent, the token is not DPoP-bound, and the request must be rejected.c. Parse DPoP Proof: Parse the DPoP header value as a JWT. Do not validate its signature yet.d. Extract Public Key: Get the jwk (JSON Web Key) from the DPoP JWT's header.12e. Validate DPoP Signature: Verify the DPoP JWT's signature using the jwk (public key) extracted from its own header.12f. Validate DPoP Claims: Verify the claims within the DPoP proof 77:htm (HTTP Method): Must exactly match the request method (e.g., "POST").htu (HTTP URI): Must exactly match the full request URI (e.g., "https://api.example.com/api/v1/users").iat (Issued At): Must be within a short, acceptable time window (e.g., 5 minutes) to prevent replay.jti (JWT ID): Must be validated for uniqueness (See Section 4.2).g. Calculate Thumbprint: Compute the SHA-256 thumbprint of the jwk (from step 3.d) as per RFC 7638.h. Token Binding Check: This is the core DPoP validation. The provider must assert that the calculated jkt from the DPoP proof (step 3.g) is identical to the jkt value extracted from the access token's cnf claim (step 3.b).12i. Success/Failure: If all checks pass, a fully authenticated JwtAuthenticationToken is returned. If any check fails, an OAuth2AuthenticationException is thrown 43, resulting in a 401 Unauthorized response.3.3. Distributed Token Revocation (Blocklist)In a stateless, horizontally-scaled environment, a token (which is valid until its exp claim) must be explicitly blocklisted upon logout or revocation. A "distributed local cache" pattern will be used, combining the high-speed reads of a local Caffeine cache with the synchronization capabilities of Kafka.33Caffeine Cache Bean: A Cache<String, Boolean> bean named revokedTokensCache will be defined.80 Its expireAfterWrite duration will be set to match or exceed the maximum JWT lifespan.Logout Endpoint: A custom POST /api/v1/auth/logout endpoint will be created.It extracts the jti (JWT ID) 82 from the authenticated AuthenticationPrincipal.It calculates the token's remaining validity (exp timestamp - now()).It publishes a TokenRevocationEvent(jti, remainingValidity) message to a Kafka topic named token-revocation-events.Kafka Listener: A @KafkaListener(topics = "token-revocation-events") 33 will be implemented in a @Component.Upon receiving a TokenRevocationEvent, this listener will update its local revokedTokensCache: revokedTokensCache.put(event.getJti(), true);.79This ensures that every node in the cluster receives the revocation message and updates its local blocklist.Security Filter (TokenBlocklistFilter):A custom OncePerRequestFilter 83 will be created and placed before the main JWT/DPoP validation filters in the SecurityFilterChain.It will perform a lightweight parse of the JWT only to extract the jti claim.It checks the local cache: if (revokedTokensCache.getIfPresent(jti)!= null).85If the jti is found in the cache, the token has been revoked. The filter immediately rejects the request with a 401 Unauthorized, short-circuiting any further processing.3.4. Session Metadata ValidationThis requirement provides an additional layer of application-level token binding, locking a token to the specific browser tab and IP address that first used it. This thwarts token theft scenarios where an attacker might capture a valid DPoP-bound token.Caffeine Cache Bean: A Cache<String, SessionMetadata> bean named sessionMetadataCache will be defined.51SessionMetadata will be a Java 21 record defined as: record SessionMetadata(String tabId, String clientIp) {}.The cache's expiry will be set to the token's exp time to automatically evict stale entries.87Security Filter (SessionValidationFilter):This custom filter will be placed after the successful DPoP validation (Section 3.2).It extracts the jti from the AuthenticationPrincipal, the tabId from the X-Tab-ID request header, and the clientIp from request.getRemoteAddr().It queries the local cache: SessionMetadata metadata = sessionMetadataCache.getIfPresent(jti);.First-Time Use (Cache Miss):If metadata == null, this is the first time this token (identified by jti) is being used.The metadata is cached: sessionMetadataCache.put(jti, new SessionMetadata(tabId, clientIp));.The request is allowed to proceed.Subsequent Use (Cache Hit):If metadata!= null, the token has been used before.The filter performs the validation: if (!metadata.tabId().equals(tabId) ||!metadata.clientIp().equals(clientIp)).On Mismatch: This indicates a potential token theft. The filter rejects the request with a 401 Unauthorized and immediately publishes the token's jti to the token-revocation-events Kafka topic (from Section 3.3). This permanently and globally blocks the compromised token.Section IV: Resource Server API and Payload SecurityThe system requires a non-standard, application-level hybrid encryption protocol. This operates in addition to TLS and DPoP, providing end-to-end encryption of the payload itself.4.1. Hybrid RSA-AES Encryption ProtocolThis protocol uses RSA for secure key exchange and AES for efficient content encryption.10 The Spring Boot application will use RequestBodyAdvice and ResponseBodyAdvice to transparently decrypt requests and encrypt responses.RSA Key Pair: The Spring server will generate a 2048-bit RSA key pair on startup or, for production, load it from a secure Java Keystore.91Public Key Endpoint: A @GetMapping("/api/v1/security/public-key") 92 will be created. This endpoint is unsecured and exposes the RSAPublicKey 93 in PEM format. The Angular client will fetch and cache this key on application startup.Encrypted DTO: A common DTO will be used for all encrypted requests:Java// Java 21 Record
record EncryptedPayload(String encryptedKey, String encryptedPayload) {}
Decryption (CustomRequestBodyAdvice):A @ControllerAdvice class implementing RequestBodyAdvice 94 will be created.supports(): This advice will be configured to intercept only methods annotated with a custom @EncryptedRequest (which will be applied to POST/PUT/DELETE controllers).beforeBodyRead(): This method intercepts the raw request body.It deserializes the body into the EncryptedPayload DTO.It uses the server's RSAPrivateKey and Cipher.getInstance("RSA/ECB/PKCS1Padding") to decrypt the encryptedKey string.95 This reveals the one-time, per-request AES session key.It uses this AES key (as a SecretKeySpec 96) and Cipher.getInstance("AES/CBC/PKCS5Padding") to decrypt the encryptedPayload string.Crucially, it stores the decrypted AES key for the response: httpServletRequest.setAttribute("request_aes_key", aesKey);.It returns the decrypted JSON payload (as a string) to the Spring framework, which then proceeds with normal JSON-to-DTO deserialization.Encryption (CustomResponseBodyAdvice):A @ControllerAdvice class implementing ResponseBodyAdvice 97 will be created, targeting the same @EncryptedRequest annotation.beforeBodyWrite(): This method intercepts the response DTO just before serialization.It retrieves the AES key: SecretKeySpec aesKey = (SecretKeySpec) httpServletRequest.getAttribute("request_aes_key");.If the key exists, it serializes the body (the response DTO) to JSON.It encrypts this JSON string using the retrieved aesKey.96It returns the Base64-encoded encrypted string as the new HTTP response body.4.2. Replay Attack ProtectionTo protect against an attacker capturing and replaying an entire EncryptedPayload blob, a nonce and timestamp must be included within the encrypted data.99Client-Side: The Angular interceptor, before AES encrypting the JSON body, will add nonce: crypto.randomUUID() and timestamp: Date.now() to the payload.Server-Side (CustomRequestBodyAdvice): The RequestBodyAdvice from Section 4.1, after decrypting the AES payload, will perform the following additional steps:Extract the nonce and timestamp from the decrypted JSON.Validate Timestamp: if (timestamp < (System.currentTimeMillis() - 5_MINUTES)) throw an exception (request is too old).100Validate Nonce: A Cache<String, Boolean> bean named nonceCache (using Caffeine with a 5-minute expiry) will be used.100if (nonceCache.getIfPresent(nonce)!= null) throw an exception (replay attack detected).If the nonce is new, store it: nonceCache.put(nonce, true);.Section V: Resource Server Business Logic and DataThis section details the implementation of core business workflows, data modeling, and external API integrations.5.1. Maker-Checker (Dual-Control) WorkflowThe user creation process requires a dual-control (Maker-Checker) workflow. This is a state-driven process, and Spring Statemachine 101 is the ideal framework for managing this, as it provides a robust, auditable, and explicit model for state transitions.JPA Entity: The User entity will be modified to support this workflow.104Java@Entity
@Table(name = "app_user")
public class User {
    //... standard fields

    @Enumerated(EnumType.STRING)
    private ApprovalStatus status; // Enum: PENDING, APPROVED, REJECTED

    @ManyToOne
    @JoinColumn(name = "maker_id")
    private User maker;

    @ManyToOne
    @JoinColumn(name = "checker_id")
    private User checker;
}
State Machine Configuration: A state machine will be defined with:States: PENDING, APPROVED, REJECTED.Events: APPROVE, REJECT.Transitions:PENDING -> APPROVED on APPROVE event.PENDING -> REJECTED on REJECT event.Workflow Implementation:Maker: A "Maker" (via POST /api/v1/users) triggers the UserService. This service creates a new User entity, associates it with a new state machine instance, sets the initial status = PENDING, and saves it to the database. No Keycloak user is created at this time.Checker: A "Checker" (via POST /api/v1/users/{id}/approve) triggers the UserService. The service retrieves the User and its associated state machine, then sends the APPROVE event.State Listener: A @WithStateMachine listener is configured to detect state transitions. When it detects a successful transition to the APPROVED state, it triggers the KeycloakUserService.Provisioning: The KeycloakUserService then calls the Keycloak Admin API to create the user in Keycloak, setting the temporary password and required action as defined in Section 2.7.User Updates: Per the requirement, user updates (e.g., PUT /api/v1/users/{id}) by a Maker do not require checker approval. This endpoint will simply call the HRMS API (if internal) for validation, update the JPA entity, and (if necessary) call the Keycloak Admin API to sync profile changes.5.2. External API Integration (HRMS & Role Validation)All external HTTP-based integrations will use the non-blocking, reactive WebClient 7, configured as a Spring bean.HRMS API Call: During the "Maker" step of internal user creation, the UserService will use the WebClient to fetch and validate details:JavaHrmsDetails details = webClient.get()
   .uri("/hrms-api/employee/{pfId}", pfId)
   .retrieve()
   .bodyToMono(HrmsDetails.class)
   .block(); //.block() is acceptable in a standard @Service
Conditional Role Validation: This requirement represents dynamic, fine-grained authorization. This will be implemented using a custom AuthorizationManager in Spring Security 6.107A class ExternalRoleAuthorizationManager will implement AuthorizationManager<RequestAuthorizationContext>.It will be injected with the WebClient and the UserRepository.In its check() method, it will:Get the authenticated Authentication principal and the target role from the request.Fetch the User's business-specific data (Branch, ESG code) from the database.Call the external role validation API using WebClient.Execute the complex conditional logic (e.g., if (role.equals("CIT") && user.getBranchId().equals(cpc.getBranchId()) && user.getEsgCode().matches("3|4") &&...)).Return a new AuthorizationDecision(true) or new AuthorizationDecision(false).This manager is then wired into the SecurityFilterChain for the specific role assignment endpoints.5.3. Bulk User Creation (External Users)An endpoint POST /api/v1/users/bulk-upload (consuming multipart/form-data) will be created to handle Excel uploads.109Library: The Apache POI library 110 will be used to parse the .xlsx file.Scalability: To prevent OutOfMemoryError on large file uploads, the service must use a streaming API. Instead of loading the entire Workbook into memory, a SAX-based parser (like XSSFSheetXMLHandler) will be used to process the file row by row.109Workflow: For each valid row read from the Excel file, the service will create a User entity, set its status to PENDING_APPROVAL, and save it (in batches). This populates the "Checker's" queue, following the same workflow as a single user creation (Section 5.1). Temporary passwords are not sent until after checker approval.Section VI: Enterprise Data Model and Persistence (JPA)The persistence layer must model a complex, hierarchical location structure and intricate user-to-location mappings.6.1. Hierarchical Location Data StrategyThe system requires a deep, fixed-depth hierarchy (Circle -> Network -> Module -> etc.). A careful choice of data modeling strategy is required to balance read performance and write complexity.StrategyAdjacency List (Self-Referencing FK)Materialized Path (String Path)Nested Sets (Left/Right Bounds)Model@ManyToOne private Location parent; 112String path; (e.g., /1/4/12/)int lft, int rgt;Reads (Descendants)Slow (N+1 queries) or Fast (via Recursive CTE) 113Very Fast (WHERE path LIKE '/1/4/%') 114Extremely FastWrites (Insert/Move)Very Fast (1 row update) 115Slow (Must update all descendants) 114Extremely Slow (Must update many rows) 114JPA SupportExcellent (Native relationship)Poor (Requires manual path management)Poor (Requires manual bound management)Recommendation: The Adjacency List model is selected. While read performance for deep hierarchies can be poor with naive JPA queries (N+1 problem 113), this is solvable. The model's simplicity and direct JPA support 112 are major advantages, especially given the write-infrequent nature of location data.JPA Entity:Java@Entity
@Table(name = "location")
public class Location {
    @Id
    private Long id;
    private String name;
    private String type; // e.g., "CIRCLE", "NETWORK", "BRANCH", "CPC"
    
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private Location parent;
}
Performance Mandate: To overcome the N+1 read problem, all queries for descendants (e.g., "find all CPCs under Circle X") must be implemented in the LocationRepository as Native SQL Queries using WITH RECURSIVE Common Table Expressions (CTEs).115 This delegates the complex hierarchical traversal to the database, resulting in a single, high-performance query.6.2. Entity-Relationship Design (User, Role, Location)The following JPA entities 120 and relationships will be implemented to meet the complex business mapping rules.Key Entities: User, Role, Location (from 6.1), BPRCenter, CPC.User-Location-Role Mapping Matrix:RelationshipFromToJPA MappingCardinality & NotesUser RolesUserRole@ManyToMany 123(Many-to-Many) Uses user_roles join table.125Primary CPCUserCPC@ManyToOne(Many-to-One) For roles: COD, NCOD, CIT, CPC Head.Primary BPRUserBPRCenter@ManyToOne(Many-to-One) For role: SIO.Mapped CPCsUserCPC@ManyToMany 126(Many-to-Many) For roles: Advocate, Valuer, Vendors.Vendor EmployeesUser (Vendor)User (Employee)@OneToMany(One-to-Many) A self-referencing relationship on the User entity, where one User (with role EmpanelledVendors) is the "parent" of many other Users (with role EmpanelledVendorsEmployees).Section VII: Angular Client Architecture and ImplementationThe Angular 20 client is responsible for initiating the OIDC flow, managing tokens, and implementing the client-side portion of the DPoP and custom encryption protocols.7.1. Authentication Flow (OIDC + PKCE)The angular-oauth2-oidc library 127 will be used to manage the OIDC authentication flow.Configuration: The app.config.ts will provide the AuthService configuration, specifying the issuer (Keycloak's realm URI), clientId: 'angular-client', responseType: 'code', and scope: 'openid profile email'.PKCE: The library natively supports PKCE 8; it will automatically generate a code_verifier, hash it (S256), and send the code_challenge during the authorization request.Route Protection: An AuthGuard will protect all business routes, automatically triggering the redirect to the Keycloak login page if the user is not authenticated or their tokens have expired.7.2. DPoP and Encryption HttpInterceptorA single, unified HttpInterceptor 128 is the most complex component of the Angular application. It must execute both DPoP proof generation and hybrid encryption in the correct order.DPoP Proof Generation:On login, the client will generate a DPoP public/private key pair using crypto.subtle and store it securely (e.g., in IndexedDB).For each API request, the interceptor will 9:Retrieve the stored DPoP private key.Generate a DPoP proof JWT, signed with the private key. This JWT must contain claims for htm (request method), htu (request URL), iat (timestamp), and jti (unique ID).77Fetch the current access token: this.oauthService.getAccessToken().Clone the request, setting the required headers:TypeScriptreq = req.clone({ 
  setHeaders: { 
    'Authorization': `DPoP ${accessToken}`,
    'DPoP': dpopProofJwt 
  }
});
Hybrid Payload Encryption:After the DPoP headers are set, the interceptor checks: `if (req.method === 'POST' || req.method === 'PUT' || req.method === 'DELETE').10 *   **Encryption (Request):** *   Generate a one-time, 32-byte AES key: const aesKey = CryptoJS.lib.WordArray.random(32);.[89, 130] *   Encrypt the request body: const encryptedBody = CryptoJS.AES.encrypt(JSON.stringify(req.body), aesKey).toString();.[131] *   Encrypt the AES key: Use the **jsencrypt** library [132, 133] and the server's cached RSA public key: const encryptedKey = jsencrypt.encrypt(aesKey.toString(CryptoJS.enc.Hex));. *   Create the new payload: const payload = { encryptedKey, encryptedPayload: encryptedBody };. *   Clone the request *again*: req = req.clone({ body: payload });. *   **Crucial:** Store the aesKeyin aMap<HttpRequest, any>to decrypt the corresponding response. *   **Decryption (Response):** *   The interceptor uses anrxjs/mapoperator on the response. *   It retrieves theaesKeyfrom theMapbased on the request. *   If anaesKeyexists and the response body is an encrypted string: *  const decryptedBody = CryptoJS.AES.decrypt(response.body, aesKey).toString(CryptoJS.enc.Utf8);.[131] *   It returns response.clone({ body: JSON.parse(decryptedBody) });` to provide the deserialized, plaintext object to the application service.7.3. Session Metadata HandlingTo support the server-side session validation (Section III.4), the client must send a unique, persistent tabId on every request.SessionService: A global service will be created. On instantiation (once per browser tab), it generates and stores a UUID: this.tabId = crypto.randomUUID();.HttpInterceptor Integration: The interceptor from 7.2 will be injected with SessionService.Header Injection: On every outgoing request, the interceptor will add the tabId as a custom header 129:TypeScriptreq = req.clone({ 
  setHeaders: { 'X-Tab-ID': this.sessionService.getTabId() } 
});
Using a custom header is more explicit and simpler for the server-side filter to parse than HttpContext.135Section VIII: Implementation Blueprints and Project ScaffoldingThis section provides the concrete project skeletons for the three primary codebases.8.1. Backend Project Structure (Spring Boot Multi-Module)Based on a Clean Architecture multi-module Maven design.23/spring-resource-server/ (Parent POM)

|-- pom.xml
|-- /app-domain/
| |-- pom.xml
| |-- /src/main/java/.../domain/
| | |-- /model/ (Entities: User, Location, CPC)
| | |-- /repository/ (Interfaces: UserRepository, LocationRepository)
| | `-- /service/ (Use Case Interfaces: UserOnboardingUseCase)
|-- /app-application/
| |-- pom.xml
| |-- /src/main/java/.../application/
| | |-- /service/ (Implementations: UserOnboardingService)
| | `-- /statemachine/ (MakerCheckerStateMachineConfig)
|-- /app-infrastructure/
| |-- pom.xml
| |-- /src/main/java/.../infrastructure/
| | |-- /persistence/ (JPA Repositories: JpaUserRepository)
| | |-- /messaging/ (Kafka: TokenRevocationListener) 
| | `-- /client/ (WebClient: HrmsApiClient, KeycloakAdminClient)
`-- /app-bootstrap/

|-- pom.xml
|-- /src/main/java/.../bootstrap/
| |-- Application.java (@SpringBootApplication)
| |-- /config/ (SecurityConfig, DpopProviderConfig, CacheConfig)
| `-- /web/ (Controllers, RequestBodyAdvice, ResponseBodyAdvice)
8.2. Frontend Project Structure (Angular)Based on a layered, feature-based Clean Architecture design.21/angular-client/

|-- /src/app/
| |-- /core/
| | |-- /auth/ (AuthService, AuthGuard, OIDC config)
| | |-- /interceptors/ (DpopEncryptionInterceptor.ts)
| | `-- /services/ (SessionService.ts - for TabId)
| |-- /domain/
| | |-- /models/ (user.model.ts, location.model.ts)
| | `-- /state/ (ngrx-store: user.actions.ts, user.reducer.ts)
| |-- /infrastructure/
| | `-- /data-access/ (user.service.ts, location.service.ts)
| |-- /features/
| | |-- /user-management/
| | | |-- /components/ (user-form, approval-queue)
| | | |-- /containers/ (user-list-page, user-create-page)
| | | `-- /facades/ (user-management.facade.ts)
| | `-- /dashboard/
| `-- /shared/ (Reusable UI components, pipes, directives)
|-- angular.json
`-- package.json
8.3. Keycloak SPI Project StructureA standard Java Maven project containing all custom SPI implementations.22/keycloak-spis/

|-- pom.xml (Dependencies: keycloak-server-spi, caffeine, java-http-client)
|-- /src/main/java/.../spi/
| |-- /captcha/ (CustomCaptchaAuthenticator.java, CustomCaptchaFactory.java)
| |-- /audit/ (AuditLoginListenerProvider.java, AuditLoginListenerFactory.java)
| |-- /session/ (SingleSessionConsenter.java, SingleSessionConsenterFactory.java)
| `-- /federation/ (ExternalUserStorageProvider.java, ExternalUserStorageFactory.java)
`-- /src/main/resources/
    `-- /META-INF/services/

|-- org.keycloak.authentication.AuthenticatorFactory
|-- org.keycloak.events.EventListenerProviderFactory
        `-- org.keycloak.storage.UserStorageProviderFactory
Section IX: Future-State Considerations9.1. Seamless SSO (Kerberos)The future plan to enable seamless SSO for internal users via Kerberos is a well-supported integration path in Keycloak.138Implementation Path:Active Directory: A Service Principal Name (SPN) must be created in AD for the Keycloak service, and a corresponding keytab file must be generated and securely transferred to the Keycloak server.139Keycloak (User Federation): A new "Kerberos" provider will be added to the realm's User Federation configuration.140 It will be configured with the server's SPN and the path to the keytab file.Keycloak (Authentication Flow): The custom "Internal" authentication sub-flow (from Section 2.3) will be modified. The Kerberos execution will be added as the first step (set to "Alternative").Resulting User Experience: When an internal user, already logged into their domain-joined Windows machine, accesses the Angular application, their browser will automatically perform a SPNEGO challenge-response.138 Keycloak will receive and validate the Kerberos ticket.14 If successful, the user is authenticated instantly and seamlessly, completely bypassing the CAPTCHA, username/password form, and any other login steps. If Kerberos fails, the flow simply continues to the CAPTCHA and password form as a fallback.


///////////////////////////////////////////////





# Complete Keycloak 26.4.2 Configuration Guide for OAuth 2.1 with PKCE and DPoP

## Part 1: Docker Setup

### Step 1: Create Docker Compose File

Create a file named `docker-compose.yml`:

```yaml
version: '3.8'

services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.0.4
    container_name: keycloak-oauth21
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_HTTP_PORT: 8080
      KC_HOSTNAME_STRICT: false
      KC_HOSTNAME_STRICT_HTTPS: false
      KC_HTTP_ENABLED: true
      KC_HEALTH_ENABLED: true
      KC_METRICS_ENABLED: true
      KC_LOG_LEVEL: info
    ports:
      - "8080:8080"
    command:
      - start-dev
    volumes:
      - keycloak_data:/opt/keycloak/data
    healthcheck:
      test: ["CMD-SHELL", "exec 3<>/dev/tcp/localhost/8080 && echo -e 'GET /health/ready HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && cat <&3 | grep -q '200 OK'"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 60s

volumes:
  keycloak_data:
    driver: local
```

### Step 2: Start Keycloak

```bash
# Navigate to the directory with docker-compose.yml
cd /path/to/your/keycloak/directory

# Start Keycloak
docker-compose up -d

# Check if it's running
docker-compose ps

# Watch the logs (wait for "Listening on: http://0.0.0.0:8080")
docker-compose logs -f keycloak

# Press Ctrl+C to exit logs when you see Keycloak is ready
```

Wait approximately 30-60 seconds for Keycloak to fully start.

### Step 3: Access Keycloak Admin Console

1. Open your browser and navigate to: `http://localhost:8080`
2. Click **"Administration Console"**
3. Login with:
   - **Username**: `admin`
   - **Password**: `admin`

---

## Part 2: Realm Configuration

### Step 4: Create a New Realm

1. Click the **realm dropdown** in the top-left corner (shows "Keycloak" or "master")
2. Click **"Create realm"**
3. Fill in the details:
   - **Realm name**: `secure-app-realm`
   - **Enabled**: `ON` (toggle should be on/blue)
4. Click **"Create"**

You should now see "secure-app-realm" in the realm dropdown.

---

## Part 3: Client Configuration (OAuth 2.1 with PKCE & DPoP)

### Step 5: Create Client - General Settings (Page 1 of 3)

1. In the left sidebar, click **"Clients"**
2. Click **"Create client"** button (top right)

**On the "General settings" page:**

3. **Client type**: Select `OpenID Connect` (should be selected by default)
4. **Client ID**: `angular-oauth-app`
5. **Name** (optional): `Angular OAuth 2.1 Application`
6. **Description** (optional): `Angular SPA with PKCE and DPoP`
7. Click **"Next"**

---

### Step 6: Create Client - Capability Config (Page 2 of 3) ⚠️ CRITICAL

**On the "Capability config" page:**

#### Client Authentication:
- **Client authentication**: `OFF` ✅
  - (Toggle should be OFF/gray - this makes it a public client suitable for SPAs)

#### Authorization:
- **Authorization**: `OFF` ✅
  - (Toggle should be OFF/gray)

#### Authentication Flow:
**ONLY check "Standard flow":**

- ☑️ **Standard flow** ✅ (CHECK THIS - this is the Authorization Code Flow)
- ☐ **Direct access grants** ❌ (UNCHECK THIS - not secure for SPAs!)
- ☐ **Implicit flow** ❌ (UNCHECK - deprecated in OAuth 2.1)
- ☐ **Service accounts roles** ❌ (UNCHECK - not needed for SPAs)
- ☐ **Standard Token Exchange** ❌ (UNCHECK)
- ☐ **OAuth 2.0 Device Authorization Grant** ❌ (UNCHECK)
- ☐ **OIDC CIBA Grant** ❌ (UNCHECK)

#### PKCE Method: ⚠️ REQUIRED
- **PKCE Method**: Select `S256` from the dropdown ✅
  - Click the dropdown and select **S256** (SHA-256 hashing)
  - Do NOT select "plain" - only S256 is secure

#### Require DPoP Bound Tokens: ⚠️ REQUIRED
- **Require DPoP bound tokens**: Toggle `ON` ✅
  - Click the toggle to turn it ON (should turn blue/show "On")

**Your configuration should look like this:**
```
Client authentication:        OFF
Authorization:                OFF

Authentication flow:
☑ Standard flow              ← ONLY THIS ONE CHECKED
☐ Direct access grants
☐ Implicit flow
☐ Service accounts roles
☐ Standard Token Exchange
☐ OAuth 2.0 Device Authorization Grant
☐ OIDC CIBA Grant

PKCE Method:                 S256 ▼
Require DPoP bound tokens:   [ON] (blue/enabled)
```

8. Click **"Next"**

---

### Step 7: Create Client - Login Settings (Page 3 of 3)

**On the "Login settings" page:**

#### URLs Configuration:

1. **Root URL**: 
   ```
   http://localhost:4200
   ```

2. **Home URL** (optional): Leave empty or use:
   ```
   http://localhost:4200
   ```

3. **Valid redirect URIs**: Add these (click "+ Add valid redirect URI" for each):
   ```
   http://localhost:4200/*
   http://localhost:4200/callback
   ```

4. **Valid post logout redirect URIs**: Add these:
   ```
   http://localhost:4200/*
   http://localhost:4200
   ```

5. **Web origins**: Add this (for CORS):
   ```
   http://localhost:4200
   ```
   Or use:
   ```
   +
   ```
   (The `+` symbol means "allow all origins that match redirect URIs")

6. Click **"Save"**

You'll be taken to the client details page.

---

### Step 8: Configure Advanced Client Settings

After saving, you're on the client details page. Now configure additional security settings:

#### 8.1 Advanced Tab

1. Click the **"Advanced"** tab at the top of the client details page

2. Scroll down and configure these settings:

**OAuth 2.1 Settings (should already be set from Step 6, but verify):**
- **Proof Key for Code Exchange Code Challenge Method**: `S256` ✅
- **OAuth 2.0 DPoP Bound Access Tokens**: `ON` ✅

**Access Token Settings:**
- **Access Token Lifespan**: `5 Minutes` ✅
  - This overrides realm default for this client
  - Short-lived tokens are more secure

**Refresh Token Settings:**
- **Client Session Idle**: `30 Minutes`
- **Client Session Max**: `10 Hours`

**Advanced OpenID Connect Configuration:**
- **Access Token Lifespan For Implicit Flow**: Leave default (we're not using implicit flow)

**OAuth 2.0 Mutual TLS:**
- **OAuth 2.0 Mutual TLS Certificate Bound Access Tokens Enabled**: `OFF`
  - (We're using DPoP instead of mTLS)

**Pushed Authorization Requests (PAR):**
- **Pushed Authorization Request Required**: `OFF` (optional feature)

3. Scroll to the bottom and click **"Save"**

---

### Step 9: Configure Realm Token Settings

1. In the left sidebar, click **"Realm settings"**
2. Click the **"Tokens"** tab

**Configure these settings:**

**General:**
- **Default Signature Algorithm**: `RS256` (should be default)

**Access Tokens:**
- **Access Token Lifespan**: `5 Minutes` ✅
- **Access Token Lifespan For Implicit Flow**: `15 Minutes`

**Refresh Tokens:**
- **Refresh Token Max Reuse**: `0` ✅ (one-time use only)
- **Revoke Refresh Token**: `ON` ✅ (toggle should be blue/enabled)

**Session Settings:**
- **SSO Session Idle**: `30 Minutes`
- **SSO Session Max**: `10 Hours`

3. Click **"Save"**

---

### Step 10: Configure Security Defenses

1. Still in **"Realm settings"**, click the **"Security defenses"** tab

**Headers Section:**
- **X-Frame-Options**: `SAMEORIGIN`
- **Content-Security-Policy**: (leave default or customize as needed)
- **Content-Security-Policy-Report-Only**: (leave empty)
- **X-Content-Type-Options**: `nosniff`
- **X-Robots-Tag**: `none`
- **X-XSS-Protection**: `1; mode=block`
- **Strict-Transport-Security**: Leave empty (enable in production with HTTPS)

**Brute Force Detection:**
- **Enabled**: `ON` ✅ (toggle on/blue)
- **Permanent lockout**: `OFF`
- **Max login failures**: `5`
- **Wait increment**: `60 Seconds`
- **Quick login check milliseconds**: `1000`
- **Minimum quick login wait**: `60 Seconds`
- **Max wait**: `15 Minutes`
- **Failure reset time**: `12 Hours`

2. Click **"Save"**

---

## Part 4: User Configuration

### Step 11: Create Test User

1. In the left sidebar, click **"Users"**
2. Click **"Add user"** button

**User Details:**
3. **Username**: `testuser` ✅ (required)
4. **Email**: `testuser@example.com`
5. **First name**: `Test`
6. **Last name**: `User`
7. **Email verified**: Toggle `ON` ✅ (turn it blue/enabled)
8. **Enabled**: Should be `ON` by default ✅

9. Click **"Create"**

### Step 12: Set User Password

After creating the user, you'll be on the user details page:

1. Click the **"Credentials"** tab
2. Click **"Set password"** button

**Password Configuration:**
3. **Password**: `Test123!`
4. **Password confirmation**: `Test123!`
5. **Temporary**: Toggle `OFF` ✅ (so user doesn't need to change password on first login)

6. Click **"Save"**
7. In the confirmation dialog, click **"Save password"**

---

## Part 5: Verification

### Step 13: Verify OpenID Configuration

1. Open a new browser tab and visit:
   ```
   http://localhost:8080/realms/secure-app-realm/.well-known/openid-configuration
   ```

2. **Verify these fields are present** in the JSON response:

**DPoP Support:**
```json
"dpop_signing_alg_values_supported": ["RS256", "PS256", "ES256"]
```

**PKCE Support:**
```json
"code_challenge_methods_supported": ["plain", "S256"]
```

**Supported Grant Types:**
```json
"grant_types_supported": [
  "authorization_code",
  "implicit",
  "refresh_token",
  "password",
  "client_credentials",
  "urn:ietf:params:oauth:grant-type:device_code",
  "urn:openid:params:grant-type:ciba"
]
```
(Note: Even though these are listed, your client is configured to ONLY use `authorization_code`)

**Authorization Endpoint:**
```json
"authorization_endpoint": "http://localhost:8080/realms/secure-app-realm/protocol/openid-connect/auth"
```

**Token Endpoint:**
```json
"token_endpoint": "http://localhost:8080/realms/secure-app-realm/protocol/openid-connect/token"
```

### Step 14: Verify Client Configuration

1. Go back to Keycloak Admin Console
2. Navigate to **Clients** → **angular-oauth-app**
3. Verify the **Settings** tab shows:
   - ✅ Client authentication: OFF
   - ✅ Standard flow: ENABLED
   - ✅ Direct access grants: DISABLED
   - ✅ Valid redirect URIs: `http://localhost:4200/*`
   - ✅ Web origins: `http://localhost:4200`

4. Click the **Advanced** tab and verify:
   - ✅ PKCE Code Challenge Method: S256
   - ✅ OAuth 2.0 DPoP Bound Access Tokens: ON
   - ✅ Access Token Lifespan: 5 Minutes

---

## Configuration Summary

### ✅ What You've Configured:

| Component | Setting | Value | Purpose |
|-----------|---------|-------|---------|
| **Realm** | Name | secure-app-realm | Isolation boundary |
| **Client Type** | Protocol | OpenID Connect | OAuth 2.0/OIDC |
| **Client Auth** | Type | Public (OFF) | SPA cannot keep secrets |
| **Flow** | Enabled | Standard Flow only | Authorization Code Flow |
| **Flow** | Disabled | Direct Access, Implicit | Security - deprecated flows |
| **PKCE** | Method | S256 | SHA-256 code challenge |
| **DPoP** | Enabled | ON | Token binding |
| **Access Token** | Lifespan | 5 minutes | Short-lived for security |
| **Refresh Token** | Reuse | 0 (one-time) | Prevent replay attacks |
| **User** | Username | testuser | Test account |
| **User** | Password | Test123! | Test credentials |

---

## Next Steps

Your Keycloak is now fully configured! The key security features enabled are:

1. ✅ **OAuth 2.1 Compliance**: Only secure flows enabled
2. ✅ **PKCE with S256**: Protection against code interception
3. ✅ **DPoP**: Token binding to cryptographic keys
4. ✅ **Short-lived tokens**: 5-minute access token lifespan
5. ✅ **One-time refresh tokens**: Refresh token reuse = 0
6. ✅ **Brute force protection**: Account lockout after failed attempts
7. ✅ **CORS configuration**: Proper web origins setup

Now you can proceed with the Angular 20 implementation that will connect to this Keycloak instance!

**Test your configuration:**
- Keycloak Admin: `http://localhost:8080/admin`
- Realm endpoint: `http://localhost:8080/realms/secure-app-realm`
- Login: `testuser` / `Test123!`
