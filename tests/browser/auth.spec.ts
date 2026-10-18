import { test, expect, type Page } from "@playwright/test";
async function openMail(page: Page, email: string, kind: string) {
  const response = await page.request.get("/__dev/mailbox");
  const messages = (await response.json()) as {
    to: string;
    kind: string;
    url: string;
  }[];
  const message = [...messages]
    .reverse()
    .find((item) => item.to === email && item.kind === kind);
  expect(message).toBeTruthy();
  await page.goto(message!.url);
}
test("registro, verificación, sesión, passkeys y recuperación desde la interfaz", async ({
  page,
  context,
}) => {
  const email = "browser@example.test";
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Bienvenido de nuevo" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Google", exact: true }),
  ).toHaveCount(0);
  await page.getByRole("button", { name: "Regístrate" }).click();
  await page.getByLabel("Nombre", { exact: true }).fill("Baul Navegador");
  await page.getByLabel("Correo electrónico").fill(email);
  await page
    .getByLabel("Contraseña", { exact: true })
    .fill("this is a long browser password");
  await page.getByRole("button", { name: "Crear cuenta", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Revisa tu correo");
  await openMail(page, email, "verify-email");
  await page.getByLabel("Correo electrónico").fill(email);
  await page
    .getByLabel("Contraseña", { exact: true })
    .fill("this is a long browser password");
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Baul Navegador" }),
  ).toBeVisible();
  await expect(page.getByText("Sesión actual")).toBeVisible();
  const cookies = await context.cookies("http://localhost:4311/api/private");
  expect(
    cookies.find((cookie) => cookie.name.endsWith("session_token"))?.httpOnly,
  ).toBe(true);
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  await page.getByRole("button", { name: "Añadir passkey" }).click();
  await expect(page.getByRole("status")).toContainText("Passkey añadida");
  await expect(page.getByText("Mi dispositivo", { exact: true })).toBeVisible();
  await page
    .getByRole("button", { name: "Cerrar sesión", exact: true })
    .click();
  await page.getByRole("button", { name: "Usar passkey" }).click();
  await expect(
    page.getByRole("heading", { name: "Baul Navegador" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Eliminar", exact: true }).click();
  await expect(page.getByText("Mi dispositivo", { exact: true })).toHaveCount(
    0,
  );
  await page
    .getByRole("button", { name: "Cerrar sesión", exact: true })
    .click();
  await page.getByRole("button", { name: "He olvidado mi contraseña" }).click();
  await page.getByLabel("Correo electrónico").fill(email);
  await page
    .getByRole("button", { name: "Enviar enlace", exact: true })
    .click();
  await expect(page.getByRole("status")).toContainText("recibirás un enlace");
  await openMail(page, email, "reset-password");
  await expect(
    page.getByRole("heading", { name: "Elige una contraseña" }),
  ).toBeVisible();
  await page
    .getByLabel("Contraseña", { exact: true })
    .fill("this is the changed browser password");
  await page.getByRole("button", { name: "Guardar contraseña" }).click();
  await expect(page.getByRole("status")).toContainText(
    "Contraseña actualizada",
  );
  await page
    .getByRole("button", { name: "Volver al inicio de sesión" })
    .click();
  await page.getByLabel("Correo electrónico").fill(email);
  await page
    .getByLabel("Contraseña", { exact: true })
    .fill("this is the changed browser password");
  await page.getByRole("button", { name: "Entrar", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Baul Navegador" }),
  ).toBeVisible();
});

test("enlace por correo y formulario móvil", async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto("/");
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  await page
    .getByRole("button", { name: "Enlace por correo", exact: true })
    .click();
  await page
    .getByLabel("Correo electrónico")
    .fill("magic-browser@example.test");
  await page.getByRole("button", { name: "Enviar enlace de acceso" }).click();
  await expect(page.getByRole("status")).toContainText("Revisa tu correo");
  await openMail(page, "magic-browser@example.test", "magic-link");
  await expect(
    page.getByRole("heading", { name: "Sesiones abiertas" }),
  ).toBeVisible();
});

test("logo y paleta configurables en acceso y cuenta, sin perder el formulario", async ({
  page,
}) => {
  const logo =
    "data:image/svg+xml," +
    encodeURIComponent(
      '<svg xmlns="http://www.w3.org/2000/svg" width="72" height="36"><rect width="72" height="36" fill="navy"/></svg>',
    );
  await page.goto("/");
  await page.getByLabel("Correo electrónico").fill("branding@example.test");
  await page.getByLabel("Paleta", { exact: true }).selectOption("night");
  await page.getByLabel("URL del logo").fill(logo);
  await expect(
    page.getByRole("img", { name: "Logo personalizado" }),
  ).toBeVisible();
  await expect(page.locator(".bouncer-mark")).toHaveCount(0);
  await expect(page.locator(".bouncer")).toHaveCSS(
    "background-color",
    "rgb(23, 32, 51)",
  );
  await expect(
    page.getByRole("button", { name: "Entrar", exact: true }),
  ).toHaveCSS("background-color", "rgb(165, 180, 252)");
  await expect(page.getByLabel("Correo electrónico")).toHaveValue(
    "branding@example.test",
  );
  await page.getByLabel("Paleta", { exact: true }).selectOption("default");
  await page.getByLabel("URL del logo").fill("");
  await expect(page.locator(".bouncer-mark")).toBeVisible();
  await expect(
    page.getByRole("img", { name: "Logo personalizado" }),
  ).toHaveCount(0);
  await expect(page.locator(".bouncer")).toHaveCSS(
    "background-color",
    "rgb(255, 255, 255)",
  );
  await expect(page.getByLabel("Correo electrónico")).toHaveValue(
    "branding@example.test",
  );
  await page
    .getByRole("button", { name: "Enlace por correo", exact: true })
    .click();
  await page.getByLabel("Correo electrónico").fill("branding@example.test");
  await page.getByRole("button", { name: "Enviar enlace de acceso" }).click();
  await expect(page.getByRole("status")).toContainText("Revisa tu correo");
  await openMail(page, "branding@example.test", "magic-link");
  await expect(
    page.getByRole("heading", { name: "Sesiones abiertas" }),
  ).toBeVisible();
  await page.getByLabel("Paleta", { exact: true }).selectOption("night");
  await page.getByLabel("URL del logo").fill(logo);
  await expect(page.locator(".bouncer-account")).toHaveCSS(
    "background-color",
    "rgb(23, 32, 51)",
  );
  await expect(
    page.getByRole("img", { name: "Logo personalizado" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Cerrar sesión", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Bienvenido de nuevo" }),
  ).toBeVisible();
  await expect(page.locator(".bouncer")).toHaveCSS(
    "background-color",
    "rgb(23, 32, 51)",
  );
  await expect(
    page.getByRole("img", { name: "Logo personalizado" }),
  ).toBeVisible();
});
