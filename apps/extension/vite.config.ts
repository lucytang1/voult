import { defineConfig, type Plugin } from "vite";
import { resolve } from "node:path";
import { copyFileSync } from "node:fs";

// Copies the hand-maintained MV3 manifest into dist/ after bundling.
// The manifest is the extension's security contract (permissions, matches,
// CSP) — it is source, never generated, so review diffs to it carefully.
function copyManifest(): Plugin {
  return {
    name: "voult-copy-manifest",
    closeBundle() {
      copyFileSync(resolve(__dirname, "src/manifest.json"), resolve(__dirname, "dist/manifest.json"));
    },
  };
}

// M0 build: one Vite invocation emits the three MV3 contexts.
//  - popup: full React page (src/popup/index.html entry)
//  - service worker: single-file IIFE (no DOM, no React)
//  - content script: single-file IIFE (isolated world, no page access)
// Manifest is copied verbatim from src/manifest.json by the copy step below.
export default defineConfig({
  plugins: [copyManifest()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, "popup.html"),
        sw: resolve(__dirname, "src/background/sw.ts"),
        content: resolve(__dirname, "src/content/content.ts"),
      },
      output: {
        entryFileNames: (chunk) => {
          if (chunk.name === "sw") return "sw.js";
          if (chunk.name === "content") return "content.js";
          return "assets/[name]-[hash].js";
        },
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash].[ext]",
      },
    },
  },
  // The extension never fetches remote code (MV3 CSP: script-src 'self').
  server: { port: 5174 },
});
