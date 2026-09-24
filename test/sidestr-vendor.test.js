/**
 * The vendored sidestr engine (vendor/sidestr/) is exactly what
 * scripts/vendor-sidestr.js wrote from the pinned commits: every file's
 * SHA-256 matches PINS.json, nothing unrecorded is present, and no vendored
 * module imports code from the network (Manifest V3 forbids it).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { listVendored, PINS } from '../scripts/vendor-sidestr.js';

const base = join(dirname(fileURLToPath(import.meta.url)), '..', 'vendor', 'sidestr');
const record = JSON.parse(readFileSync(join(base, 'PINS.json'), 'utf8'));

describe('vendored sidestr engine', () => {
  it('records the pins the script names', () => {
    assert.deepEqual(record.pins.map((p) => [p.name, p.commit]), PINS.map((p) => [p.name, p.commit]));
  });

  it('every file matches its recorded SHA-256, and nothing else is present', () => {
    const recorded = [];
    for (const pin of record.pins) {
      for (const [file, sum] of Object.entries(pin.files)) {
        const path = `${pin.name}/${file}`; recorded.push(path);
        const actual = createHash('sha256').update(readFileSync(join(base, path), 'utf8')).digest('hex');
        assert.equal(actual, sum, `${path} changed since it was vendored`);
      }
    }
    assert.deepEqual(listVendored(base), recorded.sort());
  });

  it('records the two patches', () => {
    const patched = record.pins.flatMap((p) => Object.keys(p.patched).map((f) => `${p.name}/${f}`)).sort();
    assert.deepEqual(patched, ['explorer/explorer.mjs', 'spec/siding/lib/overlays/evm.mjs']);
  });

  it('no vendored module imports, fetches or evaluates code from the network', () => {
    for (const path of listVendored(base).filter((f) => /\.m?js$/.test(f))) {
      const src = readFileSync(join(base, path), 'utf8');
      assert.doesNotMatch(src, /import\s*\(\s*[`'"]https?:/, `${path} imports from the network`);
      assert.doesNotMatch(src, /from\s*['"]https?:/, `${path} imports from the network`);
      assert.doesNotMatch(src, /new Function|\beval\(/, `${path} evaluates strings`);
    }
  });

  it('the explorer defaults to the vendored engine, and the EVM rule refuses as unsupported', async () => {
    const explorer = await import('../vendor/sidestr/explorer/explorer.mjs');
    assert.match(explorer.CDN, /^file:.*\/vendor\/sidestr\/schema$/);
    assert.match(explorer.SIDESTR, /^file:.*\/vendor\/sidestr\/spec\/siding\/lib$/);
    const { evmOverlay } = await import('../vendor/sidestr/spec/siding/lib/overlays/evm.mjs');
    assert.throws(() => evmOverlay({ id: 'sidestr:x' }), (e) => e.code === 'unsupported');
  });
});
