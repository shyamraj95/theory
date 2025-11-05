sequenceDiagram
    autonumber
    actor U as User (Browser)
    participant A as Angular 20 SPA<br/>(Zoneless + Signals)
    participant K as Keycloak 26.4.2<br/>(Authorization Server)
    participant R as Protected Resource API

    Note over A: <b>Startup</b><br/>Angular 20 SPA initializes<br/>DpopService + angular-auth-oidc-client
    A->>DpopService: init()
    alt allowToRefresh = false (prod)
        DpopService->>Crypto: generateKey({extractable:false})
        Note right of DpopService: 🧬 Non-extractable ECDSA P-256 key<br/>Private key in memory only
    else allowToRefresh = true (dev)
        DpopService->>Crypto: generateKey({extractable:true})
        DpopService->>SessionStorage: save JWK (private/public)
    end

    DpopService->>DpopService: compute dpop_jkt (SHA-256 thumbprint)
    A->>A: store dpop_jkt for authorization URL

    U->>A: clicks “Login”
    A->>K: HTTPS GET /authorize?<br/>client_id, redirect_uri, code_challenge, dpop_jkt
    Note over K: PKCE S256 challenge + DPoP thumbprint sent

    K->>U: Show login UI
    U->>K: enter credentials / MFA
    K-->>A: Redirect → /callback?code=xyz

    Note over A: <b>Token Exchange</b>
    A->>DpopService: createProof('POST', /token)
    DpopService->>Crypto: sign(iat, htm, htu, jti)
    DpopService-->>A: DPoP JWT Proof (dpop+jwt)
    A->>K: HTTPS POST /token + DPoP Proof Header
    K->>K: verify DPoP JWK + jkt binding
    K-->>A: access_token (bound to jkt) + refresh_token (optional) + DPoP-Nonce

    Note over A,K: Keycloak may return DPoP-Nonce header (RFC 9449)
    A->>DpopService: setNonce(nonce)
    alt allowToRefresh=true
        A->>SessionStorage: store tokens + JWK
    else
        A->>Memory: keep tokens in-memory only
    end

    Note over A: <b>Authenticated Session</b><br/>angular-auth-oidc-client maintains token lifecycle

    U->>A: invokes Protected API call
    A->>DpopService: createProof('GET', /api/secure)
    DpopService->>Crypto: sign({htm, htu, iat, jti, nonce})
    DpopService-->>A: DPoP JWT Proof
    A->>R: HTTPS GET /api/secure <br/>Authorization: DPoP <access_token> <br/>DPoP: <proof>
    R->>R: verify proof + jkt match + nonce freshness
    R-->>A: 200 OK / DPoP-Nonce(new)
    A->>DpopService: updateNonce(new)

    Note over A,R: If nonce expired, replay attempts fail → DPoP Nonce rotation flow triggers retry.

    U->>A: clicks “Logout”
    A->>DpopService: clear() (delete keys)
    A->>SessionStorage: clear tokens (if any)
    A->>K: GET /logout?redirect_uri
    K-->>A: redirect → postLogoutRedirectUri
    Note over A: Session terminated — no private key or token remains

    %% Optional token refresh
    alt allowToRefresh=true AND refresh token valid
        A->>DpopService: createProof('POST', /token)
        A->>K: POST /token grant_type=refresh_token + DPoP Proof
        K-->>A: new access_token (bound to same jkt)
    end
