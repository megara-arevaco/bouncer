import { useId, useState, type ReactNode, type FormEvent } from "react";
import { TwoFactorChallenge } from "./security-panel.js";
import { Brand } from "./brand.js";
import { useBouncer } from "./provider.js";
type View = "login" | "register" | "forgot" | "magic" | "reset";
const titles: Record<View, string> = {
  login: "Bienvenido de nuevo",
  register: "Crea tu cuenta",
  forgot: "Recupera tu acceso",
  magic: "Entra con tu correo",
  reset: "Elige una contraseña",
};
type Result = { data?: unknown; error?: { message?: string | undefined } | null };
export function AuthPanel({
  initialView = "login",
  resetToken,
  onAuthenticated,
  logo,
}: {
  logo?: ReactNode;
  initialView?: View;
  resetToken?: string;
  onAuthenticated?: () => void;
}) {
  const { client, capabilities: c, themeStyle, callbackURL } = useBouncer();
  const passwordEnabled = c.emailPassword || c.usernamePassword;
  const [view, setView] = useState<View>(
    resetToken
      ? "reset"
      : initialView === "login" && !passwordEnabled && c.magicLink
        ? "magic"
        : initialView,
  );
  const [challenge, setChallenge] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const id = useId();
  const changeView = (next: View) => {
    setView(next);
    setError("");
    setMessage("");
  };
  const run = async (
    operation: () => Promise<Result>,
    success?: string,
    authenticated = false,
  ) => {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const result = await operation();
      if (result.error)
        setError(
          result.error.message ?? "No se ha podido completar la solicitud.",
        );
      else {
        if (success) setMessage(success);
        if (authenticated && result.data && typeof result.data === "object" && "twoFactorRedirect" in result.data && result.data.twoFactorRedirect) setChallenge(true);
        else if (authenticated) onAuthenticated?.();
      }
    } catch {
      setError("No se ha podido conectar. Inténtalo de nuevo.");
    } finally {
      setBusy(false);
    }
  };
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const values = new FormData(event.currentTarget);
    const email = String(values.get("email") ?? "").trim();
    const password = String(values.get("password") ?? "");
    if (view === "register")
      void run(
        () =>
          client.signUp.email({
            email,
            password,
            name: String(values.get("name")),
            ...(c.usernamePassword
              ? { username: String(values.get("username")) }
              : {}),
            callbackURL,
          }),
        c.requireEmailVerification
          ? "Cuenta creada. Revisa tu correo para verificarla."
          : "Cuenta creada. Ya puedes iniciar sesión.",
      );
    if (view === "login")
      void run(
        () =>
          c.usernamePassword && (!c.emailPassword || !email.includes("@"))
            ? client.signIn.username({ username: email, password })
            : client.signIn.email({ email, password }),
        undefined,
        true,
      );
    if (view === "forgot")
      void run(
        () =>
          client.requestPasswordReset({
            email,
            redirectTo: new URL(
              "reset-password",
              new URL(callbackURL, window.location.origin),
            ).href,
          }),
        "Si existe una cuenta, recibirás un enlace para recuperar el acceso.",
      );
    if (view === "magic")
      void run(
        () => client.signIn.magicLink({ email, callbackURL }),
        "Revisa tu correo para continuar.",
      );
    if (view === "reset")
      void run(
        () =>
          client.resetPassword({ newPassword: password, token: resetToken }),
        "Contraseña actualizada. Ya puedes iniciar sesión.",
      );
  };
  if (challenge) return <TwoFactorChallenge onAuthenticated={() => { setChallenge(false); onAuthenticated?.(); }} onCancel={() => setChallenge(false)} />;
  return (
    <section
      className="bouncer"
      style={themeStyle}
      aria-labelledby={`${id}-title`}
    >
      <Brand logo={logo} />
      <p className="bouncer-eyebrow">ACCEDE A TU ESPACIO</p>
      <h1 id={`${id}-title`}>{titles[view]}</h1>
      <p className="bouncer-description">
        {view === "register"
          ? "Un lugar para empezar, una cuenta para ti."
          : "Accede a tu cuenta para continuar."}
      </p>
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
      {(view === "register" && (!c.registration || !passwordEnabled)) ||
      (view === "forgot" && !c.passwordReset) ||
      (view === "reset" && !c.passwordReset) ||
      (view === "magic" && !c.magicLink) ? (
        <p>Este método no está disponible.</p>
      ) : view !== "login" || passwordEnabled ? (
        <form onSubmit={submit}>
          <fieldset disabled={busy}>
            {view === "register" && (
              <label htmlFor={`${id}-name`}>
                Nombre
                <input
                  id={`${id}-name`}
                  name="name"
                  autoComplete="name"
                  required
                  maxLength={100}
                />
              </label>
            )}
            {view === "register" && c.usernamePassword && (
              <label htmlFor={`${id}-username`}>
                Usuario
                <input
                  id={`${id}-username`}
                  name="username"
                  autoComplete="username"
                  minLength={3}
                  maxLength={40}
                  pattern={"[a-zA-Z0-9._\\-]{3,40}"}
                  required
                />
              </label>
            )}
            {view !== "reset" && (
              <label htmlFor={`${id}-email`}>
                {view === "login" && c.usernamePassword
                  ? c.emailPassword
                    ? "Correo o usuario"
                    : "Usuario"
                  : "Correo electrónico"}
                <input
                  id={`${id}-email`}
                  name="email"
                  type={
                    view === "login" && c.usernamePassword ? "text" : "email"
                  }
                  autoComplete={
                    view === "login" && c.usernamePassword
                      ? "username"
                      : "email"
                  }
                  required
                  maxLength={254}
                />
              </label>
            )}
            {["login", "register", "reset"].includes(view) && (
              <label htmlFor={`${id}-password`}>
                Contraseña
                <input
                  id={`${id}-password`}
                  name="password"
                  type="password"
                  autoComplete={
                    view === "login" ? "current-password" : "new-password"
                  }
                  minLength={view === "login" ? 1 : c.minPasswordLength}
                  maxLength={128}
                  aria-describedby={
                    view !== "login" ? `${id}-password-hint` : undefined
                  }
                  required
                />
              </label>
            )}
            {["register", "reset"].includes(view) && (
              <small id={`${id}-password-hint`}>
                Al menos {c.minPasswordLength} caracteres.
              </small>
            )}
            <button className="bouncer-primary" type="submit">
              {busy
                ? "Un momento…"
                : {
                    login: "Entrar",
                    register: "Crear cuenta",
                    forgot: "Enviar enlace",
                    magic: "Enviar enlace de acceso",
                    reset: "Guardar contraseña",
                  }[view]}
            </button>
          </fieldset>
        </form>
      ) : null}
      {view === "login" && (
        <>
          {c.passwordReset && (
            <button
              disabled={busy}
              className="bouncer-link"
              onClick={() => changeView("forgot")}
            >
              He olvidado mi contraseña
            </button>
          )}
          {(c.socialProviders.length > 0 || c.passkeys || c.magicLink) && (
            <div className="bouncer-divider">O CONTINÚA CON</div>
          )}
          <div className="bouncer-methods">
            {c.socialProviders.map((provider) => (
              <button
                disabled={busy}
                key={provider}
                onClick={() =>
                  void run(() =>
                    client.signIn.social({ provider, callbackURL }),
                  )
                }
              >
                {provider === "google" ? "Google" : "GitHub"}
              </button>
            ))}
            {c.passkeys && (
              <button
                disabled={busy}
                onClick={() =>
                  void run(() => client.signIn.passkey(), undefined, true)
                }
              >
                Usar passkey
              </button>
            )}
            {c.magicLink && (
              <button disabled={busy} onClick={() => changeView("magic")}>
                Enlace por correo
              </button>
            )}
          </div>
        </>
      )}
      <footer>
        {view === "login" ? (
          c.registration &&
          passwordEnabled && (
            <>
              ¿Aún no tienes cuenta?{" "}
              <button
                className="bouncer-link"
                disabled={busy}
                onClick={() => changeView("register")}
              >
                Regístrate
              </button>
            </>
          )
        ) : (
          <button
            className="bouncer-link"
            disabled={busy}
            onClick={() => changeView("login")}
          >
            Volver al inicio de sesión
          </button>
        )}
      </footer>
    </section>
  );
}
