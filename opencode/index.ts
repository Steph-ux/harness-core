/**
 * Entry point of the OpenCode plugin package.
 *
 * OpenCode resolves a plugin directory to a root entrypoint and ignores the
 * package manifest, so this file is what makes the package loadable.
 */
export { default } from "./plugin";
