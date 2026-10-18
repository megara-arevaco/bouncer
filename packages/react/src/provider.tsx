import {
  createContext,
  useContext,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";
import {
  QueryClient,
  QueryClientProvider,
  useQuery,
} from "@tanstack/react-query";
import type { BouncerCapabilities, BouncerClient } from "./client.js";

import { paletteStyle, type BouncerBranding } from "./theme.js";

type Config = BouncerBranding & {
  themeStyle: CSSProperties;
  client: BouncerClient;
  capabilities: BouncerCapabilities;
  appName: string;
  callbackURL: string;
};
const Context = createContext<Config | null>(null);
export function BouncerProvider({
  client,
  capabilities,
  appName,
  callbackURL = "/",
  logo,
  palette,
  children,
}: BouncerBranding & {
  client: BouncerClient;
  capabilities: BouncerCapabilities;
  appName: string;
  callbackURL?: string;
  children: ReactNode;
}) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: { queries: { retry: false, staleTime: 30_000 } },
      }),
  );
  return (
    <Context.Provider
      value={{
        client,
        capabilities,
        appName,
        callbackURL,
        logo,
        palette,
        themeStyle: paletteStyle(palette),
      }}
    >
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    </Context.Provider>
  );
}
export function useBouncer() {
  const config = useContext(Context);
  if (!config) throw new Error("Envuelve los componentes en BouncerProvider.");
  return config;
}
export function useSession() {
  return useBouncer().client.useSession();
}
export function useSessions() {
  const { client } = useBouncer();
  const { data } = client.useSession();
  return useQuery({
    queryKey: ["bouncer", "sessions", data?.user.id],
    enabled: Boolean(data),
    queryFn: async () => {
      const result = await client.listSessions();
      if (result.error) throw new Error(result.error.message);
      return result.data;
    },
  });
}
export function AuthGuard({
  children,
  fallback,
}: {
  children: ReactNode;
  fallback: ReactNode;
}) {
  const session = useSession();
  if (session.isPending && !session.isRefetching)
    return <p role="status">Comprobando sesión…</p>;
  if (session.error)
    return (
      <p role="alert">
        No se ha podido comprobar la sesión. Vuelve a intentarlo.
      </p>
    );
  return session.data ? children : fallback;
}
