import { useState } from "react";
import { useBouncer, useSession } from "./provider.js";

type Result = { error?: { message?: string } | null };
export function TwoFactorChallenge({ onAuthenticated, onCancel }: { onAuthenticated: () => void; onCancel?: () => void }) {
  const { client } = useBouncer();
  const [code, setCode] = useState("");
  const [backup, setBackup] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  return <section className="bouncer"><h2>Verifica tu identidad</h2><form onSubmit={async event => {
    event.preventDefault(); setBusy(true); setError("");
    try {
      const result = backup ? await client.twoFactor.verifyBackupCode({ code, disableSession: false }) : await client.twoFactor.verifyTotp({ code });
      if (result.error) setError("Código incorrecto o caducado.");
      else { setCode(""); onAuthenticated(); }
    } catch { setError("No se ha podido verificar el código."); }
    finally { setBusy(false); }
  }}><label>{backup ? "Código de recuperación" : "Código de tu aplicación de autenticación"}<input name="two-factor-code" autoComplete="one-time-code" inputMode={backup ? "text" : "numeric"} value={code} onChange={event => setCode(event.target.value.trim())} maxLength={64} required /></label><button disabled={busy}>Verificar código</button></form>{error && <p role="alert">{error}</p>}<button disabled={busy} onClick={() => { setBackup(!backup); setCode(""); setError(""); }}>{backup ? "Usar aplicación de autenticación" : "Usar código de recuperación"}</button>{onCancel && <button disabled={busy} onClick={onCancel}>Cancelar</button>}</section>;
}

export function SecurityPanel() {
  const { client, capabilities } = useBouncer();
  const session = useSession();
  const [password, setPassword] = useState("");
  const [nextPassword, setNextPassword] = useState("");
  const [code, setCode] = useState("");
  const [setup, setSetup] = useState<{ totpURI: string; backupCodes: string[] }>();
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const run = async (action: () => Promise<Result>, success: string) => {
    setBusy(true); setError(""); setMessage("");
    try {
      const result = await action();
      if (result.error) setError(result.error.message ?? "No se ha podido completar la operación.");
      else { setMessage(success); setPassword(""); setNextPassword(""); await session.refetch(); }
    } catch { setError("No se ha podido conectar."); }
    finally { setBusy(false); }
  };
  if (!session.data) return null;
  const enabled = session.data.user.twoFactorEnabled;
  return <section aria-label="Seguridad de la cuenta" className="bouncer-security"><h2>Seguridad</h2>
    {error && <p role="alert">{error}</p>}{message && <p role="status">{message}</p>}
    <fieldset disabled={busy}>
      <label>Contraseña para confirmar identidad<input name="security-password" type="password" autoComplete="current-password" value={password} maxLength={128} onChange={event => setPassword(event.target.value)} /></label>
      {capabilities.reauthentication && <button disabled={!password} onClick={() => void run(() => client.$fetch("/reauthenticate", { method: "POST", body: { password } }), "Identidad confirmada durante cinco minutos.")}>Confirmar identidad</button>}
      {capabilities.passwordChange && <form onSubmit={event => { event.preventDefault(); void run(() => client.changePassword({ currentPassword: password, newPassword: nextPassword, revokeOtherSessions: true }), "Contraseña actualizada. Las otras sesiones se han cerrado."); }}><label>Nueva contraseña<input name="security-new-password" type="password" autoComplete="new-password" minLength={capabilities.minPasswordLength} maxLength={128} required value={nextPassword} onChange={event => setNextPassword(event.target.value)} /></label><button disabled={!password}>Cambiar contraseña</button></form>}
      {capabilities.twoFactor && <><h3>Autenticación en dos pasos</h3><p>{enabled ? "Activada" : "Desactivada"}</p>
        {!enabled && !setup && <button disabled={!password} onClick={() => void run(async () => { const result = await client.twoFactor.enable({ password }); if (result.data && "totpURI" in result.data) setSetup(result.data); return result; }, "Añade el secreto a tu aplicación y verifica un código para activar la protección.")}>Activar autenticación en dos pasos</button>}
        {setup && <><p>Añade esta clave a tu aplicación de autenticación. Guarda los códigos de recuperación en un lugar privado antes de continuar.</p><label>Clave de configuración<input readOnly value={new URL(setup.totpURI).searchParams.get("secret") ?? ""} /></label><details><summary>Códigos de recuperación</summary><ul>{setup.backupCodes.map(value => <li key={value}><code>{value}</code></li>)}</ul></details><form onSubmit={event => { event.preventDefault(); void run(async () => { const result = await client.twoFactor.verifyTotp({ code }); if (!result.error) { setSetup(undefined); setCode(""); } return result; }, "Autenticación en dos pasos activada."); }}><label>Código de verificación<input name="enrollment-code" autoComplete="one-time-code" inputMode="numeric" pattern="[0-9]{6}" required value={code} onChange={event => setCode(event.target.value)} /></label><button>Confirmar activación</button></form></>}
        {enabled && <button disabled={!password} onClick={() => void run(() => client.twoFactor.disable({ password }), "Autenticación en dos pasos desactivada.")}>Desactivar autenticación en dos pasos</button>}
      </>}
    </fieldset>
  </section>;
}
