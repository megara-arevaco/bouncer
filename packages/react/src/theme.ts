import type { CSSProperties, ReactNode } from "react";

export type BouncerPalette = {
  accent: string;
  accentForeground: string;
  text: string;
  muted: string;
  border: string;
  surface: string;
  inputBackground: string;
  buttonBackground: string;
  hoverBackground: string;
  focusRing: string;
  errorBackground: string;
  errorText: string;
  successBackground: string;
  successText: string;
  shadow: string;
};

export type BouncerBranding = {
  logo?: ReactNode;
  palette?: Partial<BouncerPalette>;
};

export function paletteStyle(
  palette: Partial<BouncerPalette> = {},
): CSSProperties {
  return Object.fromEntries(
    Object.entries(palette)
      .filter(([, value]) => value !== undefined)
      .map(([key, value]) => [
        `--bouncer-${key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)}`,
        value,
      ]),
  ) as CSSProperties;
}
