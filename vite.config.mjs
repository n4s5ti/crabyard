import preact from "@preact/preset-vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [preact()],
  build: {
    outDir: "dist/app-bundle",
    emptyOutDir: true,
    rollupOptions: {
      external: ["/vendor/ghostty-web.js"],
      input: "src/app.html",
    },
  },
});
