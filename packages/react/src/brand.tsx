import type { ReactNode } from "react";
import { useBouncer } from "./provider.js";

export function Brand({ logo: override }: { logo?: ReactNode }) {
  const { appName, logo: providerLogo } = useBouncer();
  const logo = override === undefined ? providerLogo : override;
  return (
    <div className="bouncer-brand">
      {logo === undefined ? (
        <span className="bouncer-mark" aria-hidden="true">
          b
        </span>
      ) : logo !== null && logo !== false ? (
        <span className="bouncer-logo">{logo}</span>
      ) : null}
      <span>{appName}</span>
    </div>
  );
}
