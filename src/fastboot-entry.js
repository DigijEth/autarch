// Entry point for fastboot.js browser bundle
// Use the .mjs (ESM) build directly to avoid Node.js CJS URL import issue

export { FastbootDevice, setDebugLevel } from 'android-fastboot/dist/fastboot.mjs';
