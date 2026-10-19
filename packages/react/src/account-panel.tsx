import { useState, type ReactNode } from "react";
import { SecurityPanel } from "./security-panel.js";
import { Brand } from "./brand.js";
import { useBouncer, useSession, useSessions } from "./provider.js";
export function AccountPanel({ logo, compact = false }: { logo?: ReactNode; compact?: boolean } = {}) {
  const { client, capabilities, themeStyle } = useBouncer();
  const session = useSession();
  const sessions = useSessions();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const run = async (
    action: () => Promise<{ error?: { message?: string } | null }>,
    success?: string,
  ) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await action();
      if (result.error)
        setError(
          result.error.message ?? "No se ha podido completar la operación.",
        );
      else {
        await sessions.refetch();
        if (success) setMessage(success);
      }
    } catch {
      setError("No se ha podido conectar. Inténtalo de nuevo.");
    } finally {
      setBusy(false);
    }
  };
  if (!session.data) return null;
  return (
    <section className="bouncer bouncer-account" style={themeStyle}>
      {!compact && <Brand logo={logo} />}
      <p className="bouncer-eyebrow">TU CUENTA</p>
      {!compact && <h1>{session.data.user.name}</h1>}
      <p>{session.data.user.email}</p>
      {capabilities.usernamePassword && <Username />}
      {error && (
        <p role="alert" className="bouncer-error">
          {error}
        </p>
      )}
      {message && (
        <p role="status" className="bouncer-success">
          {message}
        </p>
      )}
      <SecurityPanel />
      <fieldset disabled={busy}>
        {capabilities.emailVerification && !session.data.user.emailVerified && (
          <button
            onClick={() =>
              void run(
                () =>
                  client.sendVerificationEmail({
                    email: session.data!.user.email,
                    callbackURL: window.location.origin,
                  }),
                "Revisa tu correo para verificar la cuenta.",
              )
            }
          >
            Verificar correo
          </button>
        )}
        <h2>Sesiones abiertas</h2>
        {sessions.isPending && <p role="status">Cargando sesiones…</p>}
        {sessions.error && (
          <p role="alert">No se han podido cargar las sesiones.</p>
        )}
        <ul>
          {sessions.data?.map((item) => (
            <li key={item.id}>
              <span>
                {item.userAgent || "Dispositivo desconocido"}
                <small>
                  {item.id === session.data?.session.id
                    ? "Sesión actual"
                    : `Última actividad: ${new Date(item.updatedAt).toLocaleString()}`}
                </small>
              </span>
              {item.id !== session.data?.session.id && (
                <button
                  onClick={() =>
                    void run(() => client.$fetch("/revoke-session-by-id", {
                      method: "POST",
                      body: { id: item.id },
                    }))
                  }
                >
                  Revocar
                </button>
              )}
            </li>
          ))}
        </ul>
        <button
          onClick={() =>
            void run(
              () => client.revokeOtherSessions(),
              "Otras sesiones cerradas.",
            )
          }
        >
          Cerrar las otras sesiones
        </button>
        {capabilities.passkeys && <Passkeys run={run} />}
        {!compact && <button
          className="bouncer-primary"
          onClick={() => void run(() => client.signOut())}
        >
          Cerrar sesión
        </button>}
      </fieldset>
    </section>
  );
}

function Passkeys({
  run,
}: {
  run: (
    action: () => Promise<{ error?: { message?: string } | null }>,
    success?: string,
  ) => Promise<void>;
}) {
  const { client } = useBouncer();
  const passkeys = client.useListPasskeys();
  return (
    <>
      <h2>Passkeys</h2>
      {passkeys.error && (
        <p role="alert">No se han podido cargar las passkeys.</p>
      )}
      <ul>
        {passkeys.data?.map((key) => (
          <li key={key.id}>
            <span>{key.name || "Passkey"}</span>
            <button
              onClick={() =>
                void run(() => client.passkey.deletePasskey({ id: key.id }))
              }
            >
              Eliminar
            </button>
          </li>
        ))}
      </ul>
      <button
        onClick={() =>
          void run(
            () => client.passkey.addPasskey({ name: "Mi dispositivo" }),
            "Passkey añadida.",
          )
        }
      >
        Añadir passkey
      </button>
    </>
  );
}

function Username() {
  const { client } = useBouncer();
  const { data } = useSession();
  const [value, setValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  if (data?.user.username)
    return (
      <p>
        Usuario: <strong>{data.user.username}</strong>
      </p>
    );
  return (
    <form
      onSubmit={async (event) => {
        event.preventDefault();
        setBusy(true);
        setError("");
        try {
          const result = await client.updateUser({ username: value });
          if (result.error)
            setError(
              result.error.message ?? "No se ha podido guardar el usuario.",
            );
        } catch {
          setError("No se ha podido conectar.");
        } finally {
          setBusy(false);
        }
      }}
    >
      <label>
        Usuario
        <input
          name="username"
          autoComplete="username"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          minLength={3}
          maxLength={40}
          pattern={"[a-zA-Z0-9._\\-]{3,40}"}
          required
        />
      </label>
      <button disabled={busy}>Guardar usuario</button>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}
