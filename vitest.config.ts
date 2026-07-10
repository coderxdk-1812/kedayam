import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    environment: "node",
    include: [
      "tests/unit/**/*.test.{js,ts}",
      "tests/redteam/**/*.test.{js,ts}",
      "tests/performance/**/*.test.{js,ts}",
      "tests/compatibility/**/*.test.{js,ts}",
      "tests/regression/**/*.test.{js,ts}",
      "tests/security/**/*.test.{js,ts}",
      "tests/resilience/**/*.test.{js,ts}",
      "tests/privacy/**/*.test.{js,ts}",
      "tests/calibration/**/*.test.{js,ts}",
      "tests/ux/**/*.test.{js,ts}",
    ],
  },
});
