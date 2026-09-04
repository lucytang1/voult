const { getDefaultConfig } = require("expo/metro-config");
const { withNativewind } = require("nativewind/metro");
const path = require("path");

/** @type {import('expo/metro-config').MetroConfig} */
const config = getDefaultConfig(__dirname);

// Monorepo: @voult/vault-core is symlinked from ../../packages/vault-core
// (outside the Expo project root). Metro must watch the workspace root and
// resolve modules from both node_modules dirs, or the symlinked package is
// invisible ("could not be found within the project").
const workspaceRoot = path.resolve(__dirname, "../..");
config.watchFolders = [workspaceRoot];
config.resolver = config.resolver || {};
config.resolver.nodeModulesPaths = [
  path.resolve(__dirname, "node_modules"),
  path.resolve(workspaceRoot, "node_modules"),
];

config.server = config.server || {};
const originalEnhanceMiddleware = config.server.enhanceMiddleware;
config.server.enhanceMiddleware = (middleware, metroServer) => {
  const finalMiddleware = originalEnhanceMiddleware
    ? originalEnhanceMiddleware(middleware, metroServer)
    : middleware;

  return (req, res, next) => {
    // Required for SharedArrayBuffer, which sqlite OPFS depends on.
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
    finalMiddleware(req, res, next);
  };
};
 
module.exports = withNativewind(config);