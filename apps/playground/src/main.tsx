import { StrictMode, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { useQuery } from "@tanstack/react-query";
import {
  BouncerProvider,
  AuthPanel,
  AccountPanel,
  createBouncerClient,
  useSession,
  type BouncerCapabilities,
  type BouncerPalette,
} from "@bouncer/react";
import "@bouncer/react/styles.css";
import "./style.css";
const client = createBouncerClient();
function Mailbox() {
  const [open, setOpen] = useState(false);
  const messages = useQuery({
    queryKey: ["dev-mailbox"],
    enabled: open,
    refetchInterval: open ? 1500 : false,
    queryFn: async () => {
      const response = await fetch("/__dev/mailbox");
      if (!response.ok) throw new Error("No se ha podido abrir el buzón.");
      return (await response.json()) as {
        to: string;
        url: string;
        kind: string;
      }[];
    },
  });
  return (
    <aside className="dev-mailbox">
      <button onClick={() => setOpen(!open)}>
        {open ? "Cerrar buzón de desarrollo" : "Abrir buzón de desarrollo"}
      </button>
      {open && (
        <>
          <p>Correos locales de prueba. No se envían mensajes reales.</p>
          {messages.error && <p role="alert">{messages.error.message}</p>}
          <ul>
            {messages.data?.map((message, i) => (
              <li key={i}>
                {message.to} · {message.kind}
                <br />
                <a href={message.url}>Abrir enlace</a>
              </li>
            ))}
          </ul>
        </>
      )}
    </aside>
  );
}
function App({ logo }: { logo?: ReactNode }) {
  const session = useSession();
  const params = new URLSearchParams(window.location.search);
  const token =
    window.location.pathname === "/reset-password"
      ? (params.get("token") ?? undefined)
      : undefined;
  return (
    <div className="playground">
      <main>
        <div className="intro">
          <span className="pill">BOUNCER</span>
          <h1>
            La puerta a<br />
            tu espacio.
          </h1>
          <p>
            Acceso sencillo.
            <br />
            Todo en su sitio.
          </p>
          <span className="intro-foot">Un módulo para cada aplicación.</span>
        </div>
        <div className="panel-area">
          {params.has("error") && (
            <p role="alert">
              El enlace no es válido o ha caducado. Solicita uno nuevo.
            </p>
          )}
          {session.isPending && !session.isRefetching ? (
            <p role="status">Comprobando sesión…</p>
          ) : session.error ? (
            <p role="alert">
              No se ha podido comprobar la sesión. Recarga la página para
              intentarlo de nuevo.
            </p>
          ) : session.data ? (
            <AccountPanel logo={logo} />
          ) : (
            <AuthPanel resetToken={token} logo={logo} />
          )}
        </div>
      </main>
      <Mailbox />
    </div>
  );
}
const nightPalette: BouncerPalette = {
  accent: "#a5b4fc",
  accentForeground: "#172033",
  text: "#f1f5f9",
  muted: "#cbd5e1",
  border: "#475569",
  surface: "#172033",
  inputBackground: "#0f172a",
  buttonBackground: "#243047",
  hoverBackground: "#334155",
  focusRing: "#c7d2fe",
  errorBackground: "#4c1d24",
  errorText: "#fecaca",
  successBackground: "#163b31",
  successText: "#bbf7d0",
  shadow: "0 16px 60px #0f172a20",
};
function Demo({ capabilities }: { capabilities: BouncerCapabilities }) {
  const [night, setNight] = useState(false);
  const [logoURL, setLogoURL] = useState("");
  return (
    <BouncerProvider
      client={client}
      capabilities={capabilities}
      appName="Bouncer"
      palette={night ? nightPalette : undefined}
      logo={
        logoURL ? <img src={logoURL} alt="Logo personalizado" /> : undefined
      }
    >
      <div className="appearance-controls">
        <div>
          <label htmlFor="demo-palette">Paleta</label>
          <select
            id="demo-palette"
            value={night ? "night" : "default"}
            onChange={(event) => setNight(event.target.value === "night")}
          >
            <option value="default">Calos (predeterminada)</option>
            <option value="night">Noche</option>
          </select>
        </div>
        <div>
          <label htmlFor="demo-logo">URL del logo</label>
          <input
            id="demo-logo"
            type="url"
            value={logoURL}
            onChange={(event) => setLogoURL(event.target.value)}
            placeholder="https://…"
          />
        </div>
      </div>
      <App
        logo={
          logoURL ? <img src={logoURL} alt="Logo personalizado" /> : undefined
        }
      />
    </BouncerProvider>
  );
}
async function start() {
  const response = await fetch("/api/auth/bouncer-config");
  if (!response.ok) throw new Error("No se ha podido cargar la configuración.");
  const capabilities = (await response.json()) as BouncerCapabilities;
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <Demo capabilities={capabilities} />
    </StrictMode>,
  );
}
void start().catch(() => {
  document.getElementById("root")!.textContent =
    "No se ha podido iniciar Bouncer. Recarga la página para intentarlo de nuevo.";
});
