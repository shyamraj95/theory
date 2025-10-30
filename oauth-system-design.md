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
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // No required actions
    }

    @Override
    public void close() {
        // Cleanup if needed
    }
}
```

#### 8.1.2 Custom Authenticator for OTP

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

public class OTPAuthenticator implements Authenticator {

    private static final String OTP_FORM = "otp-form.ftl";
    
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel user = context.getUser();
        
        // Generate and send OTP via Resource Server
        sendOTP(context.getSession(), user);
        
        Response challenge = context.form()
            .setAttribute("username", user.getUsername())
            .createForm(OTP_FORM);
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String otpCode = formData.getFirst("otpCode");
        UserModel user = context.getUser();
        
        boolean valid = validateOTP(context.getSession(), user.getId(), otpCode);
        
        if (valid) {
            context.success();
        } else {
            Response challenge = context.form()
                .setError("invalidOTP")
                .createForm(OTP_FORM);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
        }
    }
    
    private void sendOTP(KeycloakSession session, UserModel user) {
        // Call Resource Server to generate and send OTP
        // POST /api/v1/otp/generate
        // Body: { "userId": user.getId(), "deliveryMethod": "EMAIL" }
    }
    
    private boolean validateOTP(KeycloakSession session, String userId, String otpCode) {
        // Call Resource Server to validate OTP
        // POST /api/v1/otp/validate
        // Body: { "userId": userId, "otpCode": otpCode }
        return true; // Placeholder
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // Check if first login
        if (user.getFirstAttribute("firstLogin") != null && 
            user.getFirstAttribute("firstLogin").equals("true")) {
            user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        }
    }

    @Override
    public void close() {
        // Cleanup
    }
}
```

#### 8.1.3 Keycloak Realm Configuration (JSON)

```json
{
  "realm": "organization-realm",
  "enabled": true,
  "sslRequired": "external",
  "registrationAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": true,
  "editUsernameAllowed": false,
  "bruteForceProtected": false,
  "permanentLockout": false,
  "accessTokenLifespan": 1800,
  "accessTokenLifespanForImplicitFlow": 900,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 36000,
  "offlineSessionIdleTimeout": 2592000,
  "accessCodeLifespan": 60,
  "accessCodeLifespanUserAction": 300,
  "accessCodeLifespanLogin": 1800,
  "oauth2DeviceCodeLifespan": 600,
  "oauth2DevicePollingInterval": 5,
  "clients": [
    {
      "clientId": "angular-client",
      "name": "Angular Frontend",
      "enabled": true,
      "publicClient": true,
      "protocol": "openid-connect",
      "redirectUris": [
        "http://localhost:4200/*",
        "https://app.organization.com/*"
      ],
      "webOrigins": [
        "http://localhost:4200",
        "https://app.organization.com"
      ],
      "standardFlowEnabled": true,
      "implicitFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "serviceAccountsEnabled": false,
      "authorizationServicesEnabled": false,
      "attributes": {
        "pkce.code.challenge.method": "S256",
        "dpop.bound.access.tokens": "true"
      }
    }
  ],
  "authenticationFlows": [
    {
      "alias": "custom-browser-flow",
      "description": "Browser flow with CAPTCHA and OTP",
      "providerId": "basic-flow",
      "topLevel": true,
      "builtIn": false,
      "authenticationExecutions": [
        {
          "authenticator": "captcha-authenticator",
          "requirement": "REQUIRED",
          "priority": 10
        },
        {
          "authenticator": "auth-cookie",
          "requirement": "ALTERNATIVE",
          "priority": 20
        },
        {
          "authenticator": "identity-provider-redirector",
          "requirement": "ALTERNATIVE",
          "priority": 25
        },
        {
          "authenticator": "auth-username-password-form",
          "requirement": "REQUIRED",
          "priority": 30
        },
        {
          "authenticator": "otp-authenticator",
          "requirement": "CONDITIONAL",
          "priority": 40
        }
      ]
    }
  ],
  "userFederationProviders": [
    {
      "displayName": "Active Directory LDAP",
      "providerName": "ldap",
      "config": {
        "vendor": ["ad"],
        "connectionUrl": ["ldap://ad.organization.com:389"],
        "bindDn": ["CN=keycloak,CN=Users,DC=organization,DC=com"],
        "bindCredential": ["password"],
        "usersDn": ["CN=Users,DC=organization,DC=com"],
        "usernameLDAPAttribute": ["sAMAccountName"],
        "rdnLDAPAttribute": ["cn"],
        "uuidLDAPAttribute": ["objectGUID"],
        "userObjectClasses": ["person, organizationalPerson, user"],
        "editMode": ["READ_ONLY"],
        "searchScope": ["2"]
      }
    }
  ]
}
```

### 8.2 Resource Server Implementation

#### 8.2.1 Application Configuration

```yaml
# application.yml
spring:
  application:
    name: resource-server
  
  datasource:
    url: jdbc:postgresql://localhost:5432/authdb
    username: postgres
    password: password
    driver-class-name: org.postgresql.Driver
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
      connection-timeout: 30000
      idle-timeout: 600000
      max-lifetime: 1800000
  
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
    properties:
      hibernate:
        dialect: org.hibernate.dialect.PostgreSQLDialect
        format_sql: true
        jdbc:
          batch_size: 20
        order_inserts: true
        order_updates: true
  
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://localhost:8080/auth/realms/organization-realm
          jwk-set-uri: http://localhost:8080/auth/realms/organization-realm/protocol/openid-connect/certs
  
  kafka:
    bootstrap-servers: localhost:9092
    consumer:
      group-id: resource-server-group
      auto-offset-reset: earliest
      key-deserializer: org.apache.kafka.common.serialization.StringDeserializer
      value-deserializer: org.springframework.kafka.support.serializer.JsonDeserializer
      properties:
        spring.json.trusted.packages: "*"
    producer:
      key-serializer: org.apache.kafka.common.serialization.StringSerializer
      value-serializer: org.springframework.kafka.support.serializer.JsonSerializer
  
  cache:
    type: caffeine
    caffeine:
      spec: maximumSize=10000,expireAfterWrite=30m

# Encryption Configuration
encryption:
  rsa:
    public-key-path: classpath:keys/public_key.pem
    private-key-path: classpath:keys/private_key.pem
  aes:
    algorithm: AES/GCM/NoPadding
    key-size: 256

# Security Configuration
security:
  max-failed-login-attempts: 3
  account-lock-duration-days: 1
  otp:
    expiry-minutes: 5
    max-attempts: 3
  nonce:
    cache-duration-minutes: 5
  token:
    validation-window-minutes: 5

# External APIs
external:
  hrms:
    base-url: http://hrms-api.organization.com
    timeout: 5000
  sms:
    base-url: http://sms-gateway.organization.com
    timeout: 3000
  email:
    base-url: http://email-service.organization.com
    timeout: 3000

logging:
  level:
    root: INFO
    com.organization: DEBUG
    org.springframework.security: DEBUG
```

#### 8.2.2 Security Configuration

```java
package com.organization.resourceserver.config;

import com.organization.resourceserver.security.*;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final DPoPValidationFilter dPoPValidationFilter;
    private final TokenTrackingFilter tokenTrackingFilter;
    private final RequestDecryptionFilter requestDecryptionFilter;
    private final ResponseEncryptionFilter responseEncryptionFilter;
    private final CustomJwtAuthenticationConverter jwtAuthenticationConverter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.configure(http))
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/api/v1/captcha/**",
                    "/api/v1/public/**",
                    "/actuator/health",
                    "/swagger-ui/**",
                    "/v3/api-docs/**"
                ).permitAll()
                .requestMatchers("/api/v1/admin/**").hasRole("SA")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .jwtAuthenticationConverter(jwtAuthenticationConverter)
                )
            )
            .addFilterBefore(dPoPValidationFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterAfter(tokenTrackingFilter, DPoPValidationFilter.class)
            .addFilterAfter(requestDecryptionFilter, TokenTrackingFilter.class)
            .addFilterAfter(responseEncryptionFilter, RequestDecryptionFilter.class);

        return http.build();
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        return new CustomJwtAuthenticationConverter();
    }
}
```

#### 8.2.3 DPoP Validation Filter

```java
package com.organization.resourceserver.security;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Slf4j
@Component
@RequiredArgsConstructor
public class DPoPValidationFilter extends OncePerRequestFilter {

    private final JwtDecoder jwtDecoder;
    private final DPoPNonceCache nonceCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        
        String authHeader = request.getHeader("Authorization");
        String dpopHeader = request.getHeader("DPoP");
        
        // Skip validation for public endpoints
        if (isPublicEndpoint(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }
        
        if (authHeader == null || !authHeader.startsWith("DPoP ")) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing or invalid Authorization header");
            return;
        }
        
        if (dpopHeader == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing DPoP header");
            return;
        }
        
        try {
            String accessToken = authHeader.substring(5);
            
            if (!validateDPoP(dpopHeader, accessToken, request)) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid DPoP proof");
                return;
            }
            
            filterChain.doFilter(request, response);
            
        } catch (Exception e) {
            log.error("DPoP validation failed", e);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "DPoP validation failed");
        }
    }
    
    private boolean validateDPoP(String dpopProof, String accessToken, HttpServletRequest request) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(dpopProof);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            
            // 1. Validate JWK and signature
            RSAPublicKey publicKey = signedJWT.getHeader()
                .getJWK()
                .toRSAKey()
                .toRSAPublicKey();
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            
            if (!signedJWT.verify(verifier)) {
                log.error("DPoP signature verification failed");
                return false;
            }
            
            // 2. Validate htm (HTTP method)
            String htm = claims.getStringClaim("htm");
            if (!request.getMethod().equalsIgnoreCase(htm)) {
                log.error("DPoP htm mismatch: expected {}, got {}", request.getMethod(), htm);
                return false;
            }
            
            // 3. Validate htu (HTTP URI)
            String htu = claims.getStringClaim("htu");
            String requestUrl = getRequestUrl(request);
            if (!requestUrl.equals(htu)) {
                log.error("DPoP htu mismatch: expected {}, got {}", requestUrl, htu);
                return false;
            }
            
            // 4. Validate ath (access token hash)
            String ath = claims.getStringClaim("ath");
            String calculatedHash = calculateTokenHash(accessToken);
            if (!calculatedHash.equals(ath)) {
                log.error("DPoP ath mismatch");
                return false;
            }
            
            // 5. Validate jti uniqueness (replay protection)
            String jti = claims.getJWTID();
            if (!nonceCache.isNonceUnique(jti)) {
                log.error("DPoP jti replay detected: {}", jti);
                return false;
            }
            
            // 6. Validate timestamp
            long iat = claims.getIssueTime().getTime();
            long currentTime = System.currentTimeMillis();
            if (Math.abs(currentTime - iat) > 300000) { // 5 minutes
                log.error("DPoP timestamp too old or in future");
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            log.error("DPoP validation error", e);
            return false;
        }
    }
    
    private String calculateTokenHash(String token) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }
    
    private String getRequestUrl(HttpServletRequest request) {
        return request.getScheme() + "://" + 
               request.getServerName() + 
               (request.getServerPort() != 80 && request.getServerPort() != 443 
                   ? ":" + request.getServerPort() : "") +
               request.getRequestURI();
    }
    
    private boolean isPublicEndpoint(String uri) {
        return uri.startsWith("/api/v1/captcha/") ||
               uri.startsWith("/api/v1/public/") ||
               uri.startsWith("/actuator/health");
    }
}
```

#### 8.2.4 Token Tracking Filter

```java
package com.organization.resourceserver.security;

import com.organization.resourceserver.model.JwtMetadata;
import com.organization.resourceserver.model.TokenStatus;
import com.organization.resourceserver.service.TokenCacheService;
import com.organization.resourceserver.service.TokenRevocationProducer;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class TokenTrackingFilter extends OncePerRequestFilter {

    private final TokenCacheService tokenCacheService;
    private final TokenRevocationProducer revocationProducer;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt) {
            String jti = jwt.getClaimAsString("jti");
            String tabId = request.getHeader("X-Tab-ID");
            String clientIp = getClientIp(request);
            
            JwtMetadata metadata = tokenCacheService.getJwtMetadata(jti);
            
            if (metadata == null) {
                // First time seeing this token, cache it
                metadata = JwtMetadata.builder()
                    .jti(jti)
                    .tabId(tabId)
                    .clientIp(clientIp)
                    .subject(jwt.getSubject())
                    .status(TokenStatus.ACTIVE)
                    .expirationTime(jwt.getExpiresAt().toEpochMilli())
                    .build();
                
                tokenCacheService.cacheJwtMetadata(metadata);
                log.debug("Cached new token metadata: jti={}", jti);
                
            } else {
                // Validate against cached metadata
                if (metadata.getStatus() == TokenStatus.REVOKED || 
                    metadata.getStatus() == TokenStatus.BLOCKED) {
                    log.warn("Blocked/revoked token attempted: jti={}", jti);
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Token has been revoked");
                    return;
                }
                
                // Validate tab ID and IP
                if (!tabId.equals(metadata.getTabId())) {
                    log.warn("Tab ID mismatch for jti={}: expected={}, actual={}", 
                        jti, metadata.getTabId(), tabId);
                    tokenCacheService.blockToken(jti);
                    revocationProducer.revokeToken(jti, "Tab ID mismatch - suspicious activity");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid session");
                    return;
                }
                
                if (!clientIp.equals(metadata.getClientIp())) {
                    log.warn("IP address mismatch for jti={}: expected={}, actual={}", 
                        jti, metadata.getClientIp(), clientIp);
                    tokenCacheService.blockToken(jti);
                    revocationProducer.revokeToken(jti, "IP address mismatch - suspicious activity");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid session");
                    return;
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
```

#### 8.2.5 Encryption Service Implementation

```java
package com.organization.resourceserver.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.organization.resourceserver.dto.EncryptedRequest;
import com.organization.resourceserver.dto.EncryptedResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
@Service
@RequiredArgsConstructor
public class EncryptionServiceImpl implements EncryptionService {

    private final ObjectMapper objectMapper;
    
    @Value("${encryption.rsa.public-key-path}")
    private Resource publicKeyResource;
    
    @Value("${encryption.rsa.private-key-path}")
    private Resource privateKeyResource;
    
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AES_KEY_SIZE = 256;
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    @PostConstruct
    public void init() throws Exception {
        this.privateKey = loadPrivateKey();
        this.publicKey = loadPublicKey();
    }
    
    @Override
    public <T> T decryptRequest(EncryptedRequest request, Class<T> clazz) {
        try {
            // 1. Decrypt AES key using RSA private key
            byte[] encryptedKeyBytes = Base64.getDecoder().decode(request.getEncryptedKey());
            Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] aesKeyBytes = rsaCipher.doFinal(encryptedKeyBytes);
            
            // 2. Decrypt data using AES key
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            byte[] iv = Base64.getDecoder().decode(request.getIv());
            byte[] encryptedData = Base64.getDecoder().decode(request.getEncryptedData());
            
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            aesCipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);
            
            byte[] decryptedBytes = aesCipher.doFinal(encryptedData);
            String decryptedJson = new String(decryptedBytes, StandardCharsets.UTF_8);
            
            // 3. Deserialize JSON
            return objectMapper.readValue(decryptedJson, clazz);
            
        } catch (Exception e) {
            log.error("Request decryption failed", e);
            throw new RuntimeException("Failed to decrypt request", e);
        }
    }
    
    @Override
    public EncryptedResponse encryptResponse(Object payload, String aesKeyBase64) {
        try {
            // 1. Serialize payload to JSON
            String jsonPayload = objectMapper.writeValueAsString(payload);
            
            // 2. Decode AES key
            byte[] aesKeyBytes = Base64.getDecoder().decode(aesKeyBase64);
            SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
            
            // 3. Generate IV
            byte[] iv = new byte[12];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            
            // 4. Encrypt with AES-GCM
            Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);
            
            byte[] encryptedBytes = aesCipher.doFinal(jsonPayload.getBytes(StandardCharsets.UTF_8));
            
            // 5. Encode to Base64
            return EncryptedResponse.builder()
                .encryptedResponse(Base64.getEncoder().encodeToString(encryptedBytes))
                .iv(Base64.getEncoder().encodeToString(iv))
                .build();
                
        } catch (Exception e) {
            log.error("Response encryption failed", e);
            throw new RuntimeException("Failed to encrypt response", e);
        }
    }
    
    @Override
    public SecretKey generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(AES_KEY_SIZE);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate AES key", e);
        }
    }
    
    private PrivateKey loadPrivateKey() throws Exception {
        byte[] keyBytes = privateKeyResource.getContentAsByteArray();
        String privateKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s", "");
        
        byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
    
    private PublicKey loadPublicKey() throws Exception {
        byte[] keyBytes = publicKeyResource.getContentAsByteArray();
        String publicKeyPEM = new String(keyBytes, StandardCharsets.UTF_8)
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s", "");
        
        byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
}
```

#### 8.2.6 CAPTCHA Service

```java
package com.organization.resourceserver.service;

import com.organization.resourceserver.dto.CaptchaResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class CaptchaService {

    private static final String CAPTCHA_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static final int CAPTCHA_LENGTH = 6;
    private static final int WIDTH = 200;
    private static final int HEIGHT = 60;
    private static final SecureRandom random = new SecureRandom();
    
    public CaptchaResponse generateCaptcha() {
        try {
            String captchaId = UUID.randomUUID().toString();
            String captchaText = generateRandomText();
            
            BufferedImage image = new BufferedImage(WIDTH, HEIGHT, BufferedImage.TYPE_INT_RGB);
            Graphics2D g2d = image.createGraphics();
            
            // Anti-aliasing
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            
            // Background
            g2d.setColor(Color.WHITE);
            g2d.fillRect(0, 0, WIDTH, HEIGHT);
            
            // Add noise lines
            for (int i = 0; i < 10; i++) {
                g2d.setColor(getRandomColor(100, 200));
                int x1 = random.nextInt(WIDTH);
                int y1 = random.nextInt(HEIGHT);
                int x2 = random.nextInt(WIDTH);
                int y2 = random.nextInt(HEIGHT);
                g2d.drawLine(x1, y1, x2, y2);
            }
            
            // Draw text
            g2d.setFont(new Font("Arial", Font.BOLD, 30));
            for (int i = 0; i < captchaText.length(); i++) {
                g2d.setColor(getRandomColor(0, 100));
                int x = 20 + i * 30;
                int y = 35 + random.nextInt(10) - 5;
                g2d.rotate(Math.toRadians(random.nextInt(20) - 10), x, y);
                g2d.drawString(String.valueOf(captchaText.charAt(i)), x, y);
                g2d.rotate(-Math.toRadians(random.nextInt(20) - 10), x, y);
            }
            
            // Add noise dots
            for (int i = 0; i < 50; i++) {
                g2d.setColor(getRandomColor(100, 200));
                int x = random.nextInt(WIDTH);
                int y = random.nextInt(HEIGHT);
                g2d.fillOval(x, y, 2, 2);
            }
            
            g2d.dispose();
            
            // Convert to Base64
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(image, "png", baos);
            String base64Image = "data:image/png;base64," + 
                Base64.getEncoder().encodeToString(baos.toByteArray());
            
            // Cache captcha
            cacheCaptcha(captchaId, captchaText);
            
            return CaptchaResponse.builder()
                .captchaId(captchaId)
                .captchaImage(base64Image)
                .build();
                
        } catch (Exception e) {
            log.error("Failed to generate CAPTCHA", e);
            throw new RuntimeException("CAPTCHA generation failed", e);
        }
    }
    
    public boolean validateCaptcha(String captchaId, String userInput) {
        String cachedText = getCaptcha(captchaId);
        if (cachedText == null) {
            log.warn("CAPTCHA not found or expired: {}", captchaId);
            return false;
        }
        
        invalidateCaptcha(captchaId);
        boolean valid = cachedText.equalsIgnoreCase(userInput);
        
        if (!valid) {
            log.warn("CAPTCHA validation failed for: {}", captchaId);
        }
        
        return valid;
    }
    
    @Cacheable(value = "captchas", key = "#captchaId")
    public String cacheCaptcha(String captchaId, String captchaText) {
        return captchaText;
    }
    
    @Cacheable(value = "captchas", key = "#captchaId")
    public String getCaptcha(String captchaId) {
        return null; // Will be loaded from cache
    }
    
    @CacheEvict(value = "captchas", key = "#captchaId")
    public void invalidateCaptcha(String captchaId) {
        // Evict from cache
    }
    
    private String generateRandomText() {
        StringBuilder sb = new StringBuilder(CAPTCHA_LENGTH);
        for (int i = 0; i < CAPTCHA_LENGTH; i++) {
            sb.append(CAPTCHA_CHARS.charAt(random.nextInt(CAPTCHA_CHARS.length())));
        }
        return sb.toString();
    }
    
    private Color getRandomColor(int min, int max) {
        int range = max - min;
        int r = min + random.nextInt(range);
        int g = min + random.nextInt(range);
        int b = min + random.nextInt(range);
        return new Color(r, g, b);
    }
}
```