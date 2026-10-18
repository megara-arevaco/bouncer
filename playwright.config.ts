import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests/browser",
  fullyParallel: false,
  workers: 1,
  use: { baseURL: "http://localhost:4311", trace: "retain-on-failure" },
  webServer: {
    command: "npm run dev",
    url: "http://localhost:4311/api/auth/bouncer-config",
    reuseExistingServer: false,
    timeout: 60_000,
    env: { PORT: "4311", BOUNCER_SQLITE: ":memory:" },
  },
});
