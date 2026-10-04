import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// Minimal M34 test setup only: component tests for the investigation
// provenance panel. The application build still uses vite.config.ts.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
  },
});
