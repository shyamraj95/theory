# Step-by-Step Keycloak Configuration Guide for Secure OAuth 2.1/OIDC System

This guide provides a comprehensive, step-by-step walkthrough for configuring Keycloak (version 25.x, as of October 2025) as the authorization server in your scalable web application. It aligns with the system requirements: PKCE/DPOP flows for Angular 20 SPA, LDAP federation for internal users, username/password + OTP for external users, CAPTCHA validation (custom with Caffeine caching), hybrid RSA-AES encryption for login payloads, and custom styling. We'll cover base setup, realm/client config, user federation, themes, and custom SPIs (Service Provider Interfaces) for CAPTCHA, OTP, and encryption.

**Prerequisites**:
- Java 21+ installed.
- Download Keycloak 25.x from [keycloak.org/downloads](https://www.keycloak.org/downloads).
- Basic familiarity with Admin Console (accessible at `http://localhost:8080/admin` post-startup).
- For SPIs: Maven/Gradle for building JARs; access to your Caffeine service (assume integrated via a shared module or REST call).

**Environment Setup Tip**: Run in dev mode for testing: `./kc.sh start-dev --http-port=8080 --hostname-strict=false`.

## Step 1: Installation and Basic Startup
1. **Extract and Build**:
   - Unzip Keycloak to a directory (e.g., `/opt/keycloak`).
   - Build the server: `./bin/kc.sh build` (optimizes for production; run this after adding providers).

2. **Start Keycloak**:
   - Run: `./bin/kc.sh start-dev --db=dev-file` (uses H2 for dev; switch to PostgreSQL for prod via `--db=postgres --db-url=jdbc:postgresql://host:5432/keycloak`).
   - Access Admin Console: `http://localhost:8080/admin`.
   - Create admin user on first login (or pre-set via `--admin-username=admin --admin-password=admin`).

3. **Verify**: Log in with admin credentials. You should see the master realm dashboard.

## Step 2: Create and Configure a Realm
Realms isolate tenants (e.g., one per circle in your system).

1. **Create Realm**:
   - In Admin Console: Left sidebar > **Add realm** > Enter `myrealm` (or your app name) > **Create**.

2. **Basic Settings**:
   - **Realm Settings** tab:
     - **General**: Set display name (e.g., "Secure Auth Realm"), enable/disable features (e.g., enable "scripts" preview via CLI: `./kc.sh start --features=preview`).
     - **Login**: Enable "Login with email" if needed; set "Brute force detection" to ON (max failures: 5, wait: 15min) for login restrictions.
     - **Tokens**: Access Token Lifespan: 15min; Refresh Token: 1hr; Enable "Revoke refresh token" for session invalidation.
     - **Themes**: Leave default for now (customize in Step 5).
     - **Email**: Configure SMTP for OTP emails (e.g., host: smtp.gmail.com, from: no-reply@yourapp.com).

3. **Password Policy**:
   - **Password Policy** tab: Add policies (e.g., min length 8, include numbers/symbols). For external users' first-time reset, add "Force password change" as default required action.

4. **Roles Configuration**:
   - **Realm Roles** tab: Create roles like `SA`, `CA`, `Maker`, `Checker`, `COD`, `CIT`, `SIO`, `Advocate`, `Valuer`, `Empanelled Vendors`, `Empanelled Vendors Employees`.
   - For multi-role: Assign via user details later.

5. **Save Changes**: Click **Save** on each tab.

## Step 3: Configure Clients for Angular SPA
Clients represent your apps (e.g., Angular frontend, Spring Boot resource server).

1. **Create SPA Client**:
   - In realm dashboard: **Clients** > **Create client**.
   - Client type: `OpenID Connect`.
   - Client ID: `angular-frontend`.
   - **Next** > Enable "Client authentication: OFF" (public client for SPA), "Standard flow: ON" (for PKCE), "Direct access grants: OFF".
   - **Next** > Valid redirect URIs: `http://localhost:4200/*` (update for prod), Web origins: `+`.
   - **Save**.

2. **Advanced Settings**:
   - **Settings** tab:
     - Authentication flows: Standard flow (browser) = ON.
     - PKCE: Code challenge method = `S256`.
     - DPOP: Enable via attributes: Add `dpop.bound.access.tokens` = `true`.
     - Valid post-logout redirect URIs: `http://localhost:4200/*`.
   - **Mappers** tab: Create mappers for custom claims (e.g., `roles` mapper: Token Claim Name = `roles`, Claim JSON Type = `String`, Multivalued = ON, from `realm roles`).

3. **Resource Server Client** (for Spring Boot APIs):
   - Create another client: ID = `resource-server`, type = `OpenID Connect`, Client authentication = ON (confidential), Standard flow = OFF.
   - Settings: Audience = `resource-server`, add scopes.

4. **Save and Test**: Download `angular-oauth2-oidc` config from **Realm Settings** > **Keys** > **openid-connect.json`.

## Step 4: User Federation for Internal Users (LDAP)
Federate Microsoft Active Directory for internal auth.

1. **Add Provider**:
   - **User Federation** tab > **Add provider** > Select `ldap`.
   - **Save**.

2. **Configure LDAP**:
   - **Settings** tab:
     - Vendor: `Active Directory`.
     - Connection URL: `ldap://your-ad-server:389`.
     - Users DN: `OU=Users,DC=example,DC=com`.
     - Bind Type: `simple`, Bind DN: `cn=admin,dc=example,dc=com`, Bind Credential: password.
     - Authentication Type: `activeDirectory`.
     - Custom User LDAP Filter: `(sAMAccountName=%s)` (for userid).
     - Import Users: `Only on first login` (or full sync).
     - Cache Policy: `DEFAULT` (TTL: 1hr).
   - **Mappers** tab: Add mappers (e.g., Username = `sAMAccountName`, Email = `mail`).
   - **Save** > **Synchronize all users** to test.

3. **External Users (DB)**: Keycloak's built-in DB handles external users. Create via API/UI in pending state (integrate with your maker-checker).

4. **Test**: Search users in **Users** tab; attempt login with LDAP creds.

## Step 5: Customize Themes for Styling
Style the login page (e.g., branding, custom classes for encryption JS).

1. **Create Theme**:
   - In Keycloak dir: `mkdir -p themes/my-theme/login/{theme.properties,login.ftl,resources/css/login.css,resources/js/login.js}`.
   - `theme.properties`: `parent=keycloak;import=common/keycloak`.

2. **Edit Templates**:
   - `login.ftl`: Override header/form as in prior example (add logo, custom inputs).
   - Add CAPTCHA/OTP fields: `<img th:src="${captchaImage}" /> <input name="captcha_solution" class="custom-input" />` (for custom SPIs).
   - Include JS: `<script src="${url.resourcesPath}/js/login.js"></script>`.

3. **CSS/JS**:
   - `login.css`: As in prior example.
   - `login.js`: Encryption function (Web Crypto, fetch pub key from JWKS).

4. **Deploy and Assign**:
   - Copy theme dir to Keycloak's `themes/`.
   - `./bin/kc.sh build`.
   - Admin Console > **Realm Settings** > **Themes** > Login Theme = `my-theme`.
   - For dynamic: Implement ThemeSelector SPI (see Step 6).

5. **Test**: Initiate login flow; verify styling.

## Step 6: Create Custom SPIs
Build JARs for CAPTCHA (FormAction with Caffeine), OTP (FormAction with internal service), and Encryption (Authenticator for payload decryption). Use Maven; depend on `keycloak-bom:25.0.0`.

**Maven pom.xml Snippet**:
```xml
<dependencyManagement>
    <dependencies>
        <dependency><groupId>org.keycloak</groupId><artifactId>keycloak-bom</artifactId><version>25.0.0</version><type>pom</type><scope>import</scope></dependency>
    </dependencies>
</dependencyManagement>
<dependencies>
    <dependency><groupId>org.keycloak</groupId><artifactId>keycloak-server-spi</artifactId><scope>provided</scope></dependency>
    <dependency><groupId>org.keycloak</groupId><artifactId>keycloak-server-spi-private</artifactId><scope>provided</scope></dependency>
    <dependency><groupId>com.github.ben-manes.caffeine</groupId><artifactId>caffeine</artifactId><version>3.1.8</version></dependency>
    <!-- Your encryption/OTP libs -->
</dependencies>
```

### 6.1 CAPTCHA SPI (FormAction)
Generates AWT image, caches solution in Caffeine, validates.

1. **FormAction Class** (`CustomCaptchaFormAction.java`):
```java
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.ValidationContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import com.github.benmanes.caffeine.cache.Cache;
import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;
import java.io.ByteArrayOutputStream;
// ... imports for AWT

public class CustomCaptchaFormAction implements FormAction {
    private final Cache<String, String> captchaCache = Caffeine.newBuilder().expireAfterWrite(5, MINUTES).build();

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
        String sessionId = context.getAuthenticationSession().getParentSession().getId();
        String solution = generateRandomSolution(6);
        captchaCache.put(sessionId, solution);
        BufferedImage img = generateCaptchaImage(solution); // Your AWT logic
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(img, "png", baos);
        String base64 = "data:image/png;base64," + java.util.Base64.getEncoder().encodeToString(baos.toByteArray());
        form.setAttribute("captchaImage", base64);
        form.setAttribute("sessionId", sessionId);
    }

    @Override
    public void validate(ValidationContext context) {
        String sessionId = context.getHttpRequest().getDecodedFormParameters().getFirst("sessionId");
        String userSolution = context.getHttpRequest().getDecodedFormParameters().getFirst("captcha_solution");
        String cached = captchaCache.getIfPresent(sessionId);
        if (cached == null || !cached.equalsIgnoreCase(userSolution)) {
            context.validationError("Invalid CAPTCHA", context.form().createErrorPage("Invalid CAPTCHA"));
            return;
        }
        context.success();
    }

    @Override
    public void success(FormContext context) {} // No-op

    // Private helpers: generateRandomSolution, generateCaptchaImage
    private String generateRandomSolution(int length) { /* SecureRandom logic */ return "ABC123"; }
    private BufferedImage generateCaptchaImage(String text) { /* AWT drawing */ return new BufferedImage(200, 50, TYPE_INT_RGB); }

    // Other methods: configure, requiresUser, etc. - implement as needed
}
```

2. **Factory** (`CustomCaptchaFormActionFactory.java`):
```java
import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomCaptchaFormActionFactory implements FormActionFactory {
    @Override
    public FormAction create(KeycloakSession session) { return new CustomCaptchaFormAction(); }

    @Override
    public String getId() { return "custom-captcha"; }
    @Override
    public String getDisplayType() { return "Custom CAPTCHA"; }
    @Override
    public String getHelpText() { return "Generates and validates CAPTCHA"; }
    @Override
    public boolean isConfigurable() { return false; }
    @Override
    public void init(Config.Scope config) {}
    @Override
    public void postInit(KeycloakSessionFactory factory) {}
    @Override
    public void close() {}
}
```

3. **Register**: `src/main/resources/META-INF/services/org.keycloak.authentication.FormActionFactory` with `com.yourpkg.CustomCaptchaFormActionFactory`.

4. **Build/Deploy**: `mvn clean package` > Copy JAR to `providers/` > `./bin/kc.sh build`.

### 6.2 OTP SPI (FormAction for Email/SMS)
Sends OTP via internal service, validates input.

1. **FormAction Class** (`OtpFormAction.java`): Similar to CAPTCHA, but:
   - `buildPage`: If password validated, generate/send OTP (e.g., REST call to your OTP service), set note in session.
   - `validate`: Compare user input to session note; expire after 5min.
   ```java
   // In buildPage
   String otp = otpService.generateAndSend(username, "email"); // Your service
   context.getAuthenticationSession().setAuthNote("pendingOtp", otp);

   // In validate
   String userOtp = context.getHttpRequest().getDecodedFormParameters().getFirst("otp");
   String pending = context.getAuthenticationSession().getAuthNote("pendingOtp");
   if (!userOtp.equals(pending)) { context.validationError(...); }
   ```

2. **Factory**: Like CAPTCHA, ID = `otp-form`.

3. **Register/Deploy**: Same as above.

### 6.3 Encryption Validation SPI (Authenticator)
Decrypts hybrid payload in login form.

1. **Authenticator Class** (`EncryptionAuthenticator.java`): Extend `AbstractUsernameFormAuthenticator` or implement `Authenticator`.
   - `authenticate`: Render form with JS for encryption.
   - `action`: Decrypt payload (use your EncryptionService), extract username/password, proceed.
   ```java
   @Override
   public void action(AuthenticationFlowContext context) {
       MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
       String encryptedPayload = formData.getFirst("encrypted_payload");
       // Decrypt using RSA private (from Keycloak keys) and AES from form
       String decrypted = encryptionService.decrypt(encryptedPayload, formData.getFirst("encrypted_aes_key"), formData.getFirst("iv"));
       // Parse JSON, validate nonce/timestamp (<5min)
       if (valid) {
           // Set username/password in context, success()
       } else {
           context.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
       }
   }
   ```

2. **Factory**: ID = `encryption-auth`, display = "Hybrid Encryption Validator".

3. **Register/Deploy**: `META-INF/services/org.keycloak.authentication.AuthenticatorFactory`.

**Note**: For Caffeine integration, inject via session or shared bean. For HRMS/role validation, add in success().

## Step 7: Configure Authentication Flows
Integrate SPIs into flows.

1. **Copy Browser Flow**:
   - **Authentication** > **Flows** tab > **Copy** "Browser".

2. **Add Executions**:
   - In new flow: **Add execution** > Select `custom-captcha` > **Required**.
   - Add `otp-form` after "Username Password Form" > **Required**.
   - Add `encryption-auth` before "Username Password Form" > **Required**.
   - For conditional: Use "Condition" executions (e.g., for external users only).

3. **Bind Flow**:
   - **Bindings** tab > Browser Flow = your new flow.

4. **Required Actions**:
   - **Required Actions** > Add "Update Password" (default for external first-login).

5. **Test Flow**: Save > Initiate login from Angular.

## Step 8: Additional Configurations
- **Events**: **Events** tab > Config > Save to DB, add Event Listener SPI if needed for audits/Kafka.
- **Brute Force**: Realm Settings > Security Defenses > ON, failure threshold = 3.
- **Single Session**: Use session max = 1 in Tokens; custom logout event to invalidate.
- **Bulk External Users**: Use Admin REST API (`POST /admin/realms/myrealm/users`) in maker-checker.

## Step 9: Testing and Production-Readiness
1. **Test Login**:
   - From Angular: `oauthService.initCodeFlow()` > Redirect to Keycloak > Solve CAPTCHA > Enter creds/OTP (encrypted) > Back with token.
   - Verify: Internal LDAP login, external OTP, role claims in token.

2. **SPI Validation**:
   - Check logs for cache hits; simulate failures (wrong CAPTCHA → error).

3. **Prod Tips**:
   - Cluster: Use Infinispan for cache; `./bin/kc.sh start --cache=ispn`.
   - HTTPS: `--https-port=8443 --https-certificate-file=...`.
   - Metrics: Enable via `--metrics-enabled=true`.
   - Backup: Export realm JSON via Admin > **Partial export**.

4. **Troubleshoot**: Check `./bin/kc.sh logs`; use `./bin/kc.sh export --dir=backup` for realms.

This setup delivers your secure, customized Keycloak. For full JAR repos or tweaks (e.g., Kerberos SSO), provide more details! 






/////////////////////////////////////////////////


# Keycloak Configuration & SPI Creation — Step-by-step Guide

This document provides a runnable, step-by-step configuration guide to implement the **External Role Validator SPI** and to configure Keycloak flows, clients, mappers and settings necessary for your system (CPC Head / COD role verification during login). It includes exact commands, file contents, and Keycloak Admin Console steps.

---

## Summary of what you'll achieve

* Build and deploy a Keycloak Authenticator SPI (JAR) that calls an external Role Validation API during login.
* Import and enable a custom authentication flow that includes the SPI step.
* Configure a realm, client, and protocol mappers so validated role and location attributes are included in JWTs.
* Secure the external API calls with a system token or mutual TLS.

---

## Prerequisites

1. Keycloak server (recommended version compatible with SPI; example: Keycloak 20+ or vendor build).
2. Java 17+ build environment (matches Keycloak runtime; you can use Java 21 for compilation if Keycloak supports it).
3. Maven 3.8+.
4. Administrative access to Keycloak Admin Console and server filesystem.
5. External Role Validation API endpoint and credentials (system token or mTLS cert).
6. Optional: Docker / Kubernetes environment for testing.

---

# Part A — Build the SPI JAR

### 1. Create project skeleton

From your development directory, create `keycloak-external-role-validator` folder and subfolders:

```
mkdir -p keycloak-external-role-validator/src/main/java/com/spleenior/keycloak/rolevalidator
mkdir -p keycloak-external-role-validator/src/main/resources/META-INF/services
mkdir -p keycloak-external-role-validator/src/main/resources
cd keycloak-external-role-validator
```

### 2. Create `pom.xml`

Create `pom.xml` with Keycloak SPI dependencies. Use a matching Keycloak version.

```xml
<!-- copy pom content from template -->
```

(Use the pom from the SPI template; ensure `keycloak.version` matches your server.)

### 3. Add Java classes

Create the following classes in `src/main/java/com/spleenior/keycloak/rolevalidator/`:

* `ExternalRoleValidatorAuthenticator.java` (implements `Authenticator`)
* `ExternalRoleValidatorFactory.java` (implements `AuthenticatorFactory`)
* `ExternalRoleApiClient.java` (HTTP client to call role API)
* `RoleValidationResponse.java` (record / DTO)
* `CaffeineCacheProvider.java`

(Implementations are in the SPI template — use prepared code and update API URL, auth token retrieval.)

### 4. Add service provider descriptors

Create these files:

```
src/main/resources/META-INF/services/org.keycloak.authentication.AuthenticatorFactory
src/main/resources/META-INF/services/org.keycloak.authentication.Authenticator
```

Each file should contain the fully-qualified factory/authenticator class name. Example for factory file:

```
com.spleenior.keycloak.rolevalidator.ExternalRoleValidatorFactory
```

### 5. Add `external-role-validator-flow.xml`

Put the XML authentication flow definition in `src/main/resources/external-role-validator-flow.xml` (example provided in template).

### 6. Build the JAR

Run Maven:

```
mvn clean package -DskipTests
```

Output: `target/external-role-validator-1.0.0.jar` (name depends on pom).

---

# Part B — Deploy the SPI to Keycloak

### 1. Copy JAR to providers directory

On the Keycloak host:

```
scp target/external-role-validator-1.0.0.jar keycloak@keycloak-host:/opt/keycloak/providers/
```

(Adjust path if using container images or operator deployments.)

### 2. Provide any required config/secrets

* Configure environment variables or mounted secrets for `ROLE_API_TOKEN` or mTLS certs.
* Example: on systemd or container env set:

```
export EXTERNAL_ROLE_API=https://internal.api/validateRole
export ROLE_API_TOKEN=<secure-jwt-or-bearer-token>
```

### 3. Rebuild Keycloak providers & restart

If using Keycloak distribution:

```
/opt/keycloak/bin/kc.sh build
systemctl restart keycloak
# or run keycloak start command
```

If using container, rebuild image or mount provider JAR and restart pod.

### 4. Verify provider loaded

In Keycloak Admin Console → Server Info → Providers, find `External Role Validator` or check logs for provider load messages.

---

# Part C — Create Authentication Flow in Keycloak

### 1. Import or create flow

Option A — Import XML

* Admin Console → Authentication → Flows → New → Import (select `external-role-validator-flow.xml` from your build resources).

Option B — Manually create flow

* Create new flow `browser-with-role-validation` of type `basic-flow`.
* Add executions in order:

  1. `Username Password Form` — Requirement: REQUIRED
  2. `External Role Validator` (from list of authenticators) — Requirement: REQUIRED
  3. `OTP Form` (if you use OTP) — Requirement: CONDITIONAL

### 2. Configure the flow as the Realm Browser Flow

* Realm → Authentication → Bind `browser-with-role-validation` as the Browser Flow for the realm.

---

# Part D — Configure Client, Mappers, and Roles

### 1. Create roles

* Realm Roles → Add roles: `COD`, `CPC_HEAD`, and any other roles you require.

### 2. Configure client

* Clients → Your Angular client (or create a client)

  * Access Type: `public` (PKCE) or `confidential` if server-side
  * Valid Redirect URIs: `https://app.example.com/*`
  * Web Origins: `+` or specific origins

### 3. Protocol Mappers

* Client → Mappers → Add mappers:

  * **Role list**: built-in `realm roles` mapper → claim: `roles`
  * **User attributes**: create mappers for `circleId`, `branchId`, `raccpId` (claim names same)
  * **Script mapper (optional)**: bundle attributes and roles into `user_context` JSON claim.

### 4. Default role assignment during approval

When your Maker/Checker service creates or enables user in Keycloak, ensure you assign the appropriate realm roles. Sample API calls:

* Create user: `POST /admin/realms/{realm}/users` with `enabled=false` or `true` depending on strategy.
* Set attributes: `attributes: { circleId: "C001", branchId: "B123" }`
* Assign roles: `POST /admin/realms/{realm}/users/{id}/role-mappings/realm` with role representation.

---

# Part E — Secure the External Role API Integration

### 1. Use mutual TLS or system token

* Preferred: mutual TLS between Keycloak hosts and role API.
* Alternative: generate a signed system JWT (short expiry) and store as environment var.

### 2. Configure timeouts and retry policy

* In `ExternalRoleApiClient` set connect timeout = 1500ms and read timeout = 2000–3000ms.
* Keep retries minimal (max 1 retry) with exponential backoff.

### 3. Cache & failure modes

* Use Caffeine cache (15 min) in SPI.
* On API failure: choose `deny` (safer) or `allow-with-cache` (less strict). Document policy.

---

# Part F — Testing & Validation

### 1. Unit test SPI locally

* Write unit tests mocking `ExternalRoleApiClient`.

### 2. Deploy to dev realm

* Deploy SPI JAR to dev Keycloak.
* Create a test user with `primaryRole` attribute set to `COD` and username `testuser`.
* Test login with valid credentials and verify JWT contains `roles` and `circleId` claims.

### 3. Simulate invalid role

* Mock role API to return `valid=false` → ensure login is rejected and user sees appropriate error.

### 4. Load test the role API path

* Ensure role API can handle concurrent login rates; tune cache TTL accordingly.

---

# Part G — Admin & Operational Notes

* **Logging**: Use structured logging inside SPI; redact sensitive tokens.
* **Metrics**: Expose SPI metrics (calls, cache hits/misses) via Keycloak metrics if possible.
* **Rollbacks**: Remove JAR and restart Keycloak to rollback.
* **High Availability**: Run Keycloak stateless horizontally; ensure SPI configs (secrets) are available on all nodes.

---

# Appendix — Useful commands & API examples

### Keycloak Admin API examples (curl)

* Create user (disabled):

```bash
curl -X POST 'https://keycloak.example.com/admin/realms/myrealm/users' \
 -H "Authorization: Bearer $ADMIN_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"username":"pf12345","enabled":false,"attributes":{"circleId":"C001","branchId":"B123","primaryRole":"COD"}}'
```

* Enable user:

```bash
curl -X PUT 'https://keycloak.example.com/admin/realms/myrealm/users/<userid>' \
 -H "Authorization: Bearer $ADMIN_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"enabled":true}'
```

* Assign realm role:

```bash
curl -X POST 'https://keycloak.example.com/admin/realms/myrealm/users/<userid>/role-mappings/realm' \
 -H "Authorization: Bearer $ADMIN_TOKEN" \
 -H "Content-Type: application/json" \
 -d '[{"id":"<role-id>","name":"COD"}]'
```

---

/////////////////////////////////////////////////////////////




