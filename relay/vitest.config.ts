import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { generateKeyPairSync } from "node:crypto";
import { defineConfig } from "vitest/config";

// A throwaway APNs signing key for the push tests: the relay signs a JWT with it and the test
// replaces the global fetch to catch the request to Apple. Nothing leaves the test.
const apns = generateKeyPairSync("ec", { namedCurve: "P-256" });
const APNS_KEY_P8 = apns.privateKey.export({ type: "pkcs8", format: "pem" }).toString();

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
      miniflare: {
        bindings: {
          APNS_KEY_P8,
          APNS_KEY_ID: "TESTKEYID0",
          APNS_TEAM_ID: "TESTTEAM00",
          APNS_TOPIC: "com.wardenclaw.app",
        },
      },
    }),
  ],
  test: {
    testTimeout: 15_000,
  },
});
