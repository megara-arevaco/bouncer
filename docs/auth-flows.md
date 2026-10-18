# Bouncer authentication flows

Each application imports `@bouncer/react` into its frontend and `@bouncer/api` into its own API. Users, sessions, database connections, secrets, email delivery and OAuth credentials belong to that application. Bouncer is a library, not a shared authentication service.

Endpoints below use the default `/api/auth` path. The application mounts the handler, runs migrations and protects its own API routes by checking the session. React components and `AuthGuard` control the interface; authorization must also run on the server.

## Application boundary

```mermaid
flowchart LR
    subgraph A[Application A]
        AUI[Frontend with Bouncer React] --> AAPI[Application API with Bouncer API]
        AAPI --> ADB[(Application A PostgreSQL)]
        AAPI --> AMail[Application A email sender]
    end
    subgraph B[Application B]
        BUI[Frontend with Bouncer React] --> BAPI[Application API with Bouncer API]
        BAPI --> BDB[(Application B PostgreSQL)]
        BAPI --> BMail[Application B email sender]
    end
```

There is no shared user directory or cross-application session. SQLite is available for development; PostgreSQL is required by Bouncer in production.

## Method discovery and application authorization

The API exposes the policy through `GET /api/auth/bouncer-config`. When `methods` is supplied, it is an allowlist: omitted methods are disabled at the API as well as hidden by the panels. With no `methods` object, email/password is enabled, magic links follow mail availability, configured social providers are enabled, and passkeys default to enabled on a domain or localhost. Username/password always requires an explicit opt-in.

```mermaid
flowchart TD
    Start[Load application] --> Config[GET /api/auth/bouncer-config]
    Config --> Panel[Render enabled authentication methods]
    Panel --> Session[GET /api/auth/get-session]
    Session --> SignedIn{Valid session?}
    SignedIn -->|No| Login[Show AuthPanel]
    Login --> Session
    SignedIn -->|Yes| App[Show protected interface]
    App --> Request[Request application API with cookie]
    Request --> Check[Host API calls bouncer.getSession]
    Check --> Allowed{Session and resource permission valid?}
    Allowed -->|No session| Unauthorized[Return 401]
    Allowed -->|No permission| Forbidden[Return 403]
    Allowed -->|Yes| Data[Read or write authorized user data]
```

`AuthGuard` is a UI boundary. Resource permissions and roles belong to the host API. Database/capability/network failures must be handled by the host; they must not grant access.

## Email and password

Email verification is required by default. Registration does not create an authenticated session under this default. Passwords contain at least `minPasswordLength` characters (12 by default, configurable up to 128) and at most 128. They are hashed on the server. This flow requires `emailPassword`; when only `usernamePassword` is enabled, registration still uses an email but login uses the username endpoint.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant DB as Application database
    participant Mail as Application email sender
    User->>UI: Enter name, email and password
    UI->>API: POST /api/auth/sign-up/email
    API->>API: Check origin, rate limit and registration policy
    alt Registration closed or input invalid
        API-->>UI: Reject registration
    else Registration accepted
        API->>DB: Store user and password hash
        API->>Mail: Send email verification link
        API-->>UI: Account created, verification required
        Mail-->>User: Verification email
        User->>API: Open verification link
        API->>API: Validate verification token
        alt Token invalid or expired
            API-->>UI: Redirect with verification error
        else Token valid
            API->>DB: Mark email as verified
            API-->>UI: Redirect to application without signing in
        end
    end
    User->>UI: Enter email and password
    UI->>API: POST /api/auth/sign-in/email
    API->>DB: Look up account
    API->>API: Verify password and email verification status
    alt Credentials invalid or verification required
        API-->>UI: Reject login
    else Login accepted
        API->>DB: Create application session
        API-->>UI: Set HttpOnly session cookie
        UI->>API: GET /api/auth/get-session
        API-->>UI: Current user and session
    end
```

Setting `requireEmailVerification: false` changes this flow: verification is no longer a login requirement, and successful password registration can establish a session. A configured `sendMail` callback enables verification and recovery emails. With the default verification requirement, this callback is mandatory.

## Username and password

Enable `methods.usernamePassword`. Registration uses `/sign-up/email` with name, email, password and username; it follows the email-verification policy above. Usernames are immutable, normalized to lowercase and limited to 3–40 ASCII letters, digits, dots, underscores or hyphens. `/is-username-available` is disabled to avoid exposing username availability.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant DB as Application database
    User->>UI: Enter username and password
    UI->>API: POST /api/auth/sign-in/username
    API->>API: Check origin, enabled method and rate limit
    API->>DB: Find normalized username and credential account
    API->>API: Verify password and email verification policy
    alt Invalid credentials or unverified email
        opt Correct password but verification required
            API->>API: Request verification email through configured sender
        end
        API-->>UI: Reject login without creating a session
    else Login accepted
        API->>DB: Create application session
        API-->>UI: Set HttpOnly session cookie
        UI->>API: GET /api/auth/get-session
        API-->>UI: Current user and session
    end
```

When both password methods are enabled, `AuthPanel` treats an identifier containing `@` as email and other identifiers as usernames. When only username/password is enabled, it always uses username login. The registration email remains required for verification and recovery. See [configuration](../README.md#configuration) for explicit method selection.

## Google

The application supplies its own Google client ID and secret. Register the application's `/api/auth/callback/google` URL with Google. The frontend only shows Google when it appears in the API capabilities. If `methods` is supplied, set `methods.google: true` as well as providing credentials.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant Google
    participant DB as Application database
    User->>UI: Choose Google
    UI->>API: POST /api/auth/sign-in/social, provider google
    API-->>UI: Google authorization URL and OAuth state cookie
    UI->>Google: Redirect to authorization URL
    Google->>User: Authenticate and request consent
    Google-->>API: Browser callback with code and state
    API->>API: Validate OAuth state and callback
    API->>Google: Exchange code and obtain identity
    Google-->>API: Provider identity
    API->>DB: Find linked Google account
    alt Linked account exists
        API->>DB: Create application session
    else New identity, registration allowed and no account conflict
        API->>DB: Create user and Google account, then session
    else Registration closed or identity conflict
        API-->>UI: Redirect with authentication error
    end
    opt Authentication succeeded
        API-->>UI: Set HttpOnly session cookie and redirect to callbackURL
    end
```

Automatic account linking is disabled. An existing email/password account is not silently merged with a Google identity that uses the same email. Denied consent, invalid state or a failed token exchange returns an authentication error without a new session.

## GitHub

The application supplies its own GitHub client ID and secret. Register the application's `/api/auth/callback/github` URL with GitHub. The frontend only shows GitHub when it appears in the API capabilities. If `methods` is supplied, set `methods.github: true` as well as providing credentials.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant GitHub
    participant DB as Application database
    User->>UI: Choose GitHub
    UI->>API: POST /api/auth/sign-in/social, provider github
    API-->>UI: GitHub authorization URL and OAuth state cookie
    UI->>GitHub: Redirect to authorization URL
    GitHub->>User: Authenticate and request consent
    GitHub-->>API: Browser callback with code and state
    API->>API: Validate OAuth state and callback
    API->>GitHub: Exchange code and obtain identity and email
    GitHub-->>API: Provider identity
    API->>DB: Find linked GitHub account
    alt Linked account exists
        API->>DB: Create application session
    else New identity, registration allowed and no account conflict
        API->>DB: Create user and GitHub account, then session
    else Registration closed or identity conflict
        API-->>UI: Redirect with authentication error
    end
    opt Authentication succeeded
        API-->>UI: Set HttpOnly session cookie and redirect to callbackURL
    end
```

The same account-linking policy applies to GitHub. Provider credentials stay in the application API; they are never passed to React. Real Google and GitHub sign-in requires credentials and provider setup; neither provider is configured in the default playground.

## Magic link

Without an explicit `methods` object, magic links are enabled when `sendMail` is configured. With `methods`, enable `magicLink: true` and provide `sendMail`. The default expiry is five minutes, configurable between one and fifteen minutes through `magicLinkExpiresIn`. A link is short-lived, single-use and stored in hashed form. Registration policy is enforced when an unknown user redeems a link.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant DB as Application database
    participant Mail as Application email sender
    User->>UI: Enter email and request access link
    UI->>API: POST /api/auth/sign-in/magic-link
    API->>API: Check origin and rate limit
    API->>DB: Store verification record using hashed token
    API->>Mail: Send magic link
    API-->>UI: Request accepted
    Mail-->>User: Access email
    User->>API: Open /api/auth/magic-link/verify link
    API->>DB: Validate and atomically consume token
    alt Token expired, invalid or already consumed
        API-->>UI: Redirect with authentication error
    else Token accepted
        API->>DB: Find user or create one if registration allows
        alt Unknown user and registration closed
            API-->>UI: Redirect with authentication error
        else User accepted
            opt Existing account has unverified email
                API->>DB: Remove unproven password and revoke prior sessions
            end
            API->>DB: Verify email and create application session
            API-->>UI: Set HttpOnly session cookie and redirect to callbackURL
        end
    end
```

For an existing account with an unverified email, successful magic-link verification removes its existing password and revokes its previous sessions before establishing the new session. The email owner can set a password through password recovery.

## Passkeys

Passkey enrollment requires an authenticated, fresh session. A user first creates or accesses their account through another method, then selects **Add passkey** in the account panel. The browser must support WebAuthn. Use HTTPS with a domain in production or `localhost` in development; numeric IP addresses are not supported as relying-party domains.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant Device as Browser and authenticator
    participant DB as Application database
    Note over User,DB: Enroll a passkey while signed in
    User->>UI: Add passkey
    UI->>API: GET /api/auth/passkey/generate-register-options
    API->>API: Require fresh session and generate challenge
    API-->>UI: Registration options and challenge cookie
    UI->>Device: Create credential for application domain
    Device->>User: Request biometric, PIN or security key approval
    Device-->>UI: Credential and registration response
    UI->>API: POST /api/auth/passkey/verify-registration
    API->>API: Verify challenge, origin and relying party
    alt Challenge, session or attestation invalid
        API-->>UI: Reject enrollment without storing credential
    else Enrollment accepted
        API->>DB: Store public key and credential metadata
        API-->>UI: Passkey registered
    end
    Note over User,DB: Sign in with an enrolled passkey
    User->>UI: Use passkey
    UI->>API: GET /api/auth/passkey/generate-authenticate-options
    API-->>UI: Authentication challenge and challenge cookie
    UI->>Device: Request credential assertion
    Device->>User: Request approval
    Device-->>UI: Signed assertion
    UI->>API: POST /api/auth/passkey/verify-authentication
    API->>DB: Load credential public key
    API->>API: Verify assertion, challenge, origin and relying party
    alt Verification fails
        API-->>UI: No new session
    else Verification succeeds
        API->>DB: Update credential metadata and create session
        API-->>UI: Set HttpOnly session cookie
    end
```

The private key remains with the authenticator. Removing a passkey from the account panel removes its server-side credential; it does not automatically revoke existing sessions. If the browser cancels the WebAuthn prompt, the client stops before submitting a verification response.

## Password recovery

The application must serve the recovery page at the redirect URL. The current `AuthPanel` builds a `reset-password` URL relative to `callbackURL`; the playground handles `/reset-password` and passes its token to `AuthPanel` through `resetToken`.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant DB as Application database
    participant Mail as Application email sender
    User->>UI: Request password recovery with email
    UI->>API: POST /api/auth/request-password-reset
    API->>API: Check rate limit and redirect URL
    opt Eligible account exists
        API->>DB: Create expiring reset token
        API->>Mail: Send recovery link
        Mail-->>User: Recovery email
    end
    API-->>UI: Generic response regardless of account existence
    User->>API: Open recovery link
    API-->>UI: Redirect to application reset page with token
    User->>UI: Enter new password
    UI->>API: POST /api/auth/reset-password with token
    API->>API: Validate token and password
    alt Token invalid, expired or already used
        API-->>UI: Reject reset
    else Reset accepted
        API->>DB: Replace password hash and consume token
        API->>DB: Revoke existing user sessions
        API-->>UI: Password updated, sign in again
    end
```

## Password change

The client exposes `client.changePassword` when password authentication and mail delivery enable the password-management endpoints. The current `AccountPanel` does not render a password-change form; the host can provide one. This operation requires an authenticated session and the current password. Recovery above is the route for users who no longer know their password.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant DB as Application database
    User->>UI: Enter current and new password
    UI->>API: POST /api/auth/change-password with revokeOtherSessions true
    API->>API: Require session, verify current password and validate new password
    alt Session, current password or new password invalid
        API-->>UI: Reject change
    else Change accepted
        API->>DB: Replace password hash and revoke existing sessions
        API->>DB: Create replacement session for current browser
        API-->>UI: Password updated and replacement session cookie
    end
```

## Session checks and revocation

Sessions expire after seven days and can be renewed after one day of activity. Cookies are HttpOnly, use SameSite=Lax and are scoped to `/` by default (configurable through `cookiePath`); HTTPS adds the Secure attribute. Each application uses its own cookie prefix and secret.

```mermaid
sequenceDiagram
    actor User
    participant UI as Application frontend
    participant API as Application API with Bouncer
    participant DB as Application database
    UI->>API: GET /api/auth/get-session with cookie
    API->>DB: Validate session and expiry
    alt Session absent, expired or revoked
        API-->>UI: No authenticated session
    else Session valid
        API-->>UI: Current user and session
        UI->>API: GET /api/auth/list-sessions
        API->>DB: Load sessions belonging to current user
        API-->>UI: Session list
        Note over UI,DB: The operations below require a valid session
    end
    opt Valid session and revoke another session
        User->>UI: Select session to revoke
        UI->>API: POST /api/auth/revoke-session
        API->>DB: Verify ownership and remove selected session
    end
    opt Valid session and close other sessions
        User->>UI: Close other sessions
        UI->>API: POST /api/auth/revoke-other-sessions
        API->>DB: Remove other sessions belonging to current user
    end
    opt Sign out with current session
        User->>UI: Sign out
        UI->>API: POST /api/auth/sign-out
        API->>DB: Remove current session
        API-->>UI: Clear current session cookie
    end
```

For protected application endpoints, the host API passes incoming headers to `bouncer.getSession(headers)` and checks the result before accessing user data. The default cookie scope includes all application routes. When setting a narrower `cookiePath`, include both the auth endpoints and every application endpoint that needs the session cookie.

## Failure and delivery boundaries

All diagrams describe a successful mail handoff when a sender is shown. `sendMail` is supplied by the host; delivery failures must propagate and the host must provide a way to retry. Do not treat an accepted registration or generic recovery response as proof that an email was delivered. Verification, recovery and magic-link URLs carry credentials and must not appear in public logs.

Social-provider consent/callback failures and browser WebAuthn cancellation do not create a session. A consumed magic-link token cannot be reused even if subsequent account creation fails. Database and network errors require host error handling. Run `npm run docs:check` to render every Mermaid block in Chromium; this checks diagram syntax and layout, while HTTP/browser tests validate the executable flows.
