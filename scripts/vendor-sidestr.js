#!/usr/bin/env node
/**
 * Vendor the sidestr engine into vendor/sidestr/ from pinned upstream commits.
 *
 * A Manifest V3 extension may not run code it fetches from the network, and
 * the sidestr explorer and wallet load their engine from jsdelivr at run time.
 * The spend window (popup/spend.html) runs the same engine, so Podkey carries
 * pinned copies of exactly the modules it imports, and nothing else:
 *
 *   bitcoin-desktop/schema   the kernel (codec) and its JSON-LD documents
 *   sidestr/spec             siding/lib: parents, overlays, records, signing
 *   sidestr/explorer         explorer.mjs: reads and validates a chain
 *
 * Two patches, both recorded in vendor/sidestr/PINS.json:
 *   - explorer.mjs: its default engine locations point at the vendored copies
 *     instead of jsdelivr, so nothing is ever imported from the network;
 *   - siding/lib/overlays/evm.mjs: replaced by a stub, because the EVM rule
 *     imports ethereumjs from jsdelivr when it starts. A chain that names the
 *     rule is refused as `unsupported` until the rule is vendored too.
 *
 * PINS.json records a SHA-256 per file; test/sidestr-vendor.test.js checks
 * the tree against it. Run: `node scripts/vendor-sidestr.js` (needs git), optionally with
 * `--from <name>=<local clone>` per pin to read an already-reviewed clone instead of fetching.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, posix, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'vendor', 'sidestr');

export const PINS = [
  {
    name: 'schema',
    repo: 'https://github.com/bitcoin-desktop/schema',
    tag: 'v0.0.27',
    commit: 'b8cbf6337c7450fe14ddc5bce00c7280059aab5d',
    // what explorer.mjs imports from `${cdn}` (and the BLAKE2b parent's overlay)
    entries: ['codec/kernel.js', 'codec/hash.js', 'codec/nostr.js', 'codec/secp256k1.js', 'codec/interpreter.js', 'codec/overlays/knots-blake2b.js'],
    documents: ['schema/core.jsonld', 'schema/proof.jsonld', 'schema/script.jsonld', 'schema/chain.jsonld', 'schema/validate.jsonld', 'schema/overlays/knots-blake2b.jsonld'],
    licence: 'LICENSE'
  },
  {
    name: 'spec',
    repo: 'https://github.com/sidestr/spec',
    commit: '373d3eb6accd163f418e8a813052f1516a942bb3',
    // what explorer.mjs imports from `${sidestr}`, plus what the spend window uses
    entries: ['siding/lib/parents.mjs', 'siding/lib/overlay.mjs', 'siding/lib/overlays/index.mjs', 'siding/lib/txsign.mjs', 'siding/lib/announce.mjs', 'siding/lib/records.mjs', 'siding/lib/overlays/assets.mjs'],
    documents: [],
    licence: 'LICENSE'
  },
  {
    name: 'explorer',
    repo: 'https://github.com/sidestr/explorer',
    commit: 'db5a04e756243f9a73cba11b083d715c2ee3b327',
    entries: ['explorer.mjs'],
    documents: [],
    licence: 'LICENSE'
  }
];

const EVM_STUB = `// Podkey stub for siding/lib/overlays/evm.mjs. The EVM rule imports ethereumjs
// from jsdelivr when it starts, and a Manifest V3 extension may not run code
// from the network, so a chain that names the rule is refused as unsupported
// until the rule is vendored too. See scripts/vendor-sidestr.js.
export function evmOverlay (chain) {
  const e = new Error(\`\${chain?.id ?? 'this chain'} names the evm rule, which Podkey cannot run yet\`);
  e.code = 'unsupported';
  throw e;
}
`;

// relative module specifiers a file imports: static `from '…'` and `import('…')` with a literal
const importsOf = (src) => [...src.matchAll(/(?:from\s*|import\s*\(\s*)['"](\.{1,2}\/[^'"]+)['"]/g)].map((m) => m[1]);

// A repo holding the pinned commit: a local clone named with `--from <name>=<path>` (it must
// contain the commit), else a shallow fetch of just that commit. Files are always read from the
// commit object with `git show`, never from a working tree, so a local clone's edits cannot leak in.
function openPin (pin, from) {
  const local = from[pin.name];
  const dir = local ?? mkdtempSync(join(tmpdir(), `podkey-${pin.name}-`));
  const git = (...args) => execFileSync('git', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 26 }).toString();
  if (!local) { git('init', '-q'); git('fetch', '-q', '--depth', '1', pin.repo, pin.commit); }
  const found = git('rev-parse', '--verify', `${pin.commit}^{commit}`).trim();
  if (found !== pin.commit) throw new Error(`${pin.name}: ${dir} resolves ${found}, pinned ${pin.commit}`);
  return {
    read: (file) => git('show', `${pin.commit}:${file}`),
    has: (file) => { try { git('cat-file', '-e', `${pin.commit}:${file}`); return true; } catch { return false; } },
    close: () => { if (!local) rmSync(dir, { recursive: true, force: true }); }
  };
}

// the entries and every module they import, transitively, as repo-relative posix paths
function closure (repo, entries) {
  const seen = new Set(); const queue = [...entries];
  while (queue.length) {
    const file = queue.shift(); if (seen.has(file)) continue;
    if (!repo.has(file)) throw new Error(`missing ${file}`);
    seen.add(file);
    for (const spec of importsOf(repo.read(file))) queue.push(posix.normalize(posix.join(posix.dirname(file), spec)));
  }
  return [...seen].sort();
}

function patch (pin, file, text) {
  if (pin.name === 'explorer' && file === 'explorer.mjs') {
    const cdn = "export const CDN = 'https://cdn.jsdelivr.net/gh/bitcoin-desktop/schema@v0.0.27';";
    const side = /export const SIDESTR = 'https:\/\/cdn\.jsdelivr\.net\/gh\/sidestr\/spec@[0-9a-f]{40}\/siding\/lib';/;
    if (!text.includes(cdn) || !side.test(text)) throw new Error('explorer.mjs: the engine locations moved; review the patch');
    return {
      text: text
        .replace(cdn, "export const CDN = new URL('../schema', import.meta.url).href; // Podkey: the vendored engine, never the network")
        .replace(side, "export const SIDESTR = new URL('../spec/siding/lib', import.meta.url).href; // Podkey: the vendored lib"),
      note: 'engine locations point at the vendored copies instead of jsdelivr'
    };
  }
  if (pin.name === 'spec' && file === 'siding/lib/overlays/evm.mjs') {
    if (!/export function evmOverlay\(/.test(text)) throw new Error('evm.mjs: evmOverlay moved; review the stub');
    return { text: EVM_STUB, note: 'stub: the EVM rule imports ethereumjs from the network at start' };
  }
  return { text, note: null };
}

const sha256 = (s) => createHash('sha256').update(s).digest('hex');

// every file under vendor/sidestr except PINS.json, as posix paths relative to it
export function listVendored (base = out) {
  const files = [];
  const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = join(d, e.name); if (e.isDirectory()) walk(p); else files.push(relative(base, p).split('\\').join('/')); } };
  if (existsSync(base)) walk(base);
  return files.filter((f) => f !== 'PINS.json').sort();
}

function main (argv) {
  const from = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] !== '--from') throw new Error(`unknown argument ${argv[i]}; usage: vendor-sidestr.js [--from <name>=<git dir>]...`);
    const [name, dir] = String(argv[++i] ?? '').split('=');
    if (!PINS.some((p) => p.name === name) || !dir) throw new Error(`--from takes <name>=<dir>, name one of ${PINS.map((p) => p.name).join(', ')}`);
    from[name] = dir;
  }
  rmSync(out, { recursive: true, force: true });
  const record = { note: 'Generated by scripts/vendor-sidestr.js. Do not edit by hand.', pins: [] };
  for (const pin of PINS) {
    const repo = openPin(pin, from);
    try {
      const files = [...closure(repo, pin.entries), ...pin.documents, pin.licence];
      const entry = { name: pin.name, repo: pin.repo, commit: pin.commit, ...(pin.tag ? { tag: pin.tag } : {}), files: {}, patched: {} };
      for (const file of files) {
        const { text, note } = patch(pin, file, repo.read(file));
        const dest = join(out, pin.name, file);
        mkdirSync(dirname(dest), { recursive: true });
        writeFileSync(dest, text);
        entry.files[file] = sha256(text);
        if (note) entry.patched[file] = note;
      }
      record.pins.push(entry);
      console.log(`${pin.name}@${pin.commit.slice(0, 7)}: ${files.length} files`);
    } finally {
      repo.close();
    }
  }
  writeFileSync(join(out, 'PINS.json'), JSON.stringify(record, null, 2) + '\n');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main(process.argv.slice(2));
