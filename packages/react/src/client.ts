import { createAuthClient } from "better-auth/react";
import { magicLinkClient, usernameClient } from "better-auth/client/plugins";
import { passkeyClient } from "@better-auth/passkey/client";

export function createBouncerClient(
  options: { baseURL?: string; basePath?: string } = {},
) {
  return createAuthClient({
    ...options,
    plugins: [magicLinkClient(), passkeyClient(), usernameClient()],
  });
}
export type BouncerClient = ReturnType<typeof createBouncerClient>;
export type BouncerCapabilities = {
  registration: boolean;
  requireEmailVerification: boolean;
  emailPassword: boolean;
  usernamePassword: boolean;
  minPasswordLength: number;
  magicLink: boolean;
  passwordReset: boolean;
  emailVerification: boolean;
  passkeys: boolean;
  socialProviders: ("google" | "github")[];
};
