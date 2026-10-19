# Flows de autenticación de Bouncer

Cada aplicación integra `@bouncer/react` en su frontend y `@bouncer/api` en su API. Conserva su propia base de datos, usuarios, sesiones, secreto, credenciales OAuth y envío de correo. No existe un servicio central de identidad ni SSO entre aplicaciones.

Las rutas usan `basePath: "/api/auth"`. Los ejemplos del cliente y la integración completa están en [Uso de la librería](uso-libreria.md). La sesión se comprueba también en cada endpoint privado; `AuthGuard` solo controla la interfaz.

## Frontera de cada aplicación

Cada aplicación necesita su propio `appId` estable y secreto aleatorio. Los prefijos separan tablas y nombres de cookies, pero no aíslan el sistema operativo ni aplicaciones maliciosas en el mismo hostname. PostgreSQL es obligatorio con `NODE_ENV=production`; SQLite queda para desarrollo.

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

## Descubrimiento y autorización

Antes de renderizar el proveedor, consultar `GET /api/auth/bouncer-config`. Con `methods`, las claves omitidas quedan deshabilitadas también en la API. Sin ese objeto: contraseña por correo habilitada, magic link según disponibilidad de correo, proveedores según credenciales y passkeys por defecto sobre dominio/localhost. Usuario y contraseña requieren activación explícita.

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

`AuthGuard` no asigna permisos. La API anfitriona devuelve 401 sin sesión y 403 si el usuario carece de permiso sobre el recurso. Ante fallos de configuración, red o base de datos, debe impedir el acceso y mostrar un error recuperable.

## Correo y contraseña

Activar `methods.emailPassword`. Alta con nombre, correo y contraseña de 12–128 caracteres por defecto; `minPasswordLength` permite aumentar el mínimo hasta 128. Con la política predeterminada se envía verificación, no se inicia sesión al registrarse y el acceso se rechaza hasta verificar el correo.

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

`requireEmailVerification: false` permite entrar sin verificar y puede establecer sesión tras el alta. Verificar un enlace no inicia sesión automáticamente. Se requiere `sendMail` con la política predeterminada; sus fallos se propagan. Para reenviar la verificación se usa `client.sendVerificationEmail({ email, callbackURL })`.

## Usuario y contraseña

Activar `methods.usernamePassword`. El alta sigue siendo `/sign-up/email`, incluyendo `username`, nombre, correo y contraseña. El correo sigue siendo necesario para verificación y recuperación. El usuario se normaliza a minúsculas, admite 3–40 caracteres ASCII (letras, números, punto, guion y guion bajo) y es inmutable.

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

El acceso usa `client.signIn.username({ username, password })`. Si ambos métodos están activos, el panel interpreta un identificador con `@` como correo; los demás como usuario. Una cuenta sin nombre de usuario puede añadirlo desde `AccountPanel` con `client.updateUser({ username })`. No hay cambio posterior; `/is-username-available` está deshabilitado para reducir enumeración.

## Google

Configurar credenciales propias en `socialProviders.google` y activar `methods.google` si existe `methods`. Registrar exactamente `https://<dominio>/api/auth/callback/google` en Google (ajustar basePath). El cliente llama `signIn.social({ provider: "google", callbackURL })`.

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

El proveedor valida estado y callback antes de crear sesión. La vinculación automática de cuentas está desactivada: compartir correo con una cuenta existente no implica fusionarlas. Credenciales incorrectas, denegación del consentimiento o conflicto de cuenta terminan en error. `registration: false` impide altas nuevas por este método. El consentimiento real de Google requiere validación manual con credenciales propias.

## GitHub

Configurar `socialProviders.github` y `methods.github` si se usa selección explícita. Registrar `https://<dominio>/api/auth/callback/github`. El cliente llama `signIn.social({ provider: "github", callbackURL })`.

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

Aplica la misma política de vinculación y registro que en Google. Los secretos permanecen en la API; React solo recibe las capacidades. Verificar manualmente el retorno del proveedor y el caso de correo no disponible/privado con la configuración real; los tests locales no sustituyen esa prueba.

## Enlace mágico

Activar `methods.magicLink` y `sendMail`; sin `methods`, basta tener envío de correo. Solicitar con `client.signIn.magicLink({ email, callbackURL })`; el usuario abre el enlace recibido y vuelve a la aplicación con sesión. Caduca por defecto a los 300 segundos, configurable entre 60 y 900; se almacena hasheado y solo se consume una vez.

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

`registration: false` impide crear una cuenta desconocida al canjear el enlace. En una cuenta existente con correo sin verificar, el canje elimina la contraseña no demostrada y revoca sesiones anteriores antes de abrir la nueva sesión. El dueño puede fijar una contraseña mediante recuperación. Un token consumido no sirve aunque falle después la creación de cuenta; solicitar otro enlace.

## Passkeys: alta, acceso, listado y borrado

Activar `methods.passkeys`. Requiere WebAuthn y dominio HTTPS, o localhost en desarrollo; Bouncer rechaza IP numérica como relying party. Primero hay que entrar por otro método para registrar la credencial desde una sesión reciente. Configurar solo passkeys deja sin alta inicial a usuarios nuevos.

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

`client.passkey.addPasskey({ name: "Mi dispositivo" })` inicia el registro; `client.signIn.passkey()` autentica sin contraseña. `client.useListPasskeys()` lista credenciales del usuario y `client.passkey.deletePasskey({ id })` las elimina. La clave privada permanece en el autenticador; borrar una passkey no revoca sesiones ya abiertas. Cancelar el diálogo no abre sesión. Mantener un método de recuperación y planificar el dominio definitivo: cambiar el RP ID puede dejar las credenciales anteriores inutilizables.

## Recuperación de contraseña

Disponible cuando hay autenticación por contraseña y envío de correo (`capabilities.passwordReset`). `client.requestPasswordReset({ email, redirectTo })` devuelve respuesta genérica exista o no la cuenta. El anfitrión debe servir la página de recuperación y pasar el parámetro `token` a `<AuthPanel resetToken={token} />`.

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

`AuthPanel` calcula `reset-password` relativo a `callbackURL`; la barra final importa si se usa subruta. El enlace pasa por la API y redirige a esa página con token. `client.resetPassword({ newPassword, token })` consume el token, actualiza la contraseña y revoca sesiones. Token inválido, caducado o ya usado falla; volver a solicitarlo. No se inicia sesión automáticamente.

## Cambio de contraseña autenticado

El cliente expone `client.changePassword({ currentPassword, newPassword, revokeOtherSessions: true })` cuando contraseña y correo permiten los endpoints de gestión de contraseña. `AccountPanel` no trae formulario de cambio; lo implementa el anfitrión.

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

Requiere sesión y contraseña actual válida. El diagrama muestra explícitamente `revokeOtherSessions: true`: se revocan sesiones previas y se establece una sesión de reemplazo para el navegador actual. Recuperación es el camino cuando se desconoce la contraseña actual; no son operaciones intercambiables.

## Sesión, renovación y revocación

La sesión dura siete días y puede renovarse después de un día de actividad. Cookies HttpOnly, SameSite=Lax y Path=/ por defecto; Secure cuando `baseURL` usa HTTPS. `cookiePath` debe cubrir tanto autenticación como todos los endpoints que necesitan sesión.

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

Consultar con `client.getSession()` o `useSession()`. `client.listSessions()` requiere sesión; `client.revokeSession({ token })` comprueba pertenencia, `client.revokeOtherSessions()` cierra las demás y `client.signOut()` cierra la actual. Los tokens de sesiones son credenciales: no registrarlos ni enviarlos a analítica. La API privada llama `bouncer.getSession(fromNodeHeaders(req.headers))` antes de acceder a datos.

## Fallos y responsabilidad del anfitrión

`sendMail` debe esperar el resultado del proveedor y propagar fallos; una respuesta de alta o recuperación no demuestra entrega final del correo. La aplicación debe gestionar reintentos, errores de base de datos/red y cierre ordenado. No registrar URLs de verificación, magic link o recuperación, ni dejar esos parámetros en logs del proxy, analítica o Referer.

Los diagramas expresan el comportamiento esperado y no sustituyen pruebas: `npm run docs:check` renderiza todos los bloques Mermaid; `npm test` comprueba HTTP y `npm run test:e2e` el navegador. OAuth real y entrega de correo real requieren validación de la aplicación consumidora.
