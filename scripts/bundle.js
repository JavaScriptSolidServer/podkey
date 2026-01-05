#!/usr/bin/env node
/**
 * Bundle script for Podkey extension
 * Bundles npm dependencies for Chrome extension service worker
 */

import { build } from 'esbuild';
import { readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..');

async function bundle () {
  console.log('📦 Bundling Podkey extension...\n');

  try {
    // Bundle background.js with all dependencies
    await build({
      entryPoints: [join(rootDir, 'src/background.js')],
      bundle: true,
      outfile: join(rootDir, 'src/background.bundle.js'),
      format: 'esm',
      platform: 'browser',
      target: 'es2020',
      sourcemap: false,
      minify: false,
      external: ['chrome'], // Chrome APIs are available at runtime
      banner: {
        js: '// Podkey - Bundled Background Service Worker\n'
      }
    });

    console.log('✅ Background service worker bundled successfully!');
    console.log('   Output: src/background.bundle.js\n');

    // Update manifest.json to use bundled file
    const manifestPath = join(rootDir, 'manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));

    if (manifest.background.service_worker !== 'src/background.bundle.js') {
      manifest.background.service_worker = 'src/background.bundle.js';
      writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
      console.log('✅ Updated manifest.json to use bundled service worker\n');
    }

    console.log('✨ Bundling complete!');
    console.log('   You can now load the extension in Chrome.\n');

  } catch (error) {
    console.error('❌ Bundling failed:', error.message);
    process.exit(1);
  }
}

bundle();
