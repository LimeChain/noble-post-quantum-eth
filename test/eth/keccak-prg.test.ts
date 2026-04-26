import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, throws } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createKeccakPrg, PrgLifecycleError } from '../../src/utils-eth.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const fromHex0x = (s) => hexToBytes(s.startsWith('0x') ? s.slice(2) : s);

const KECCAK_PRG_VECTORS = JSON.parse(
  readFileSync(join(__dirname, 'vectors/keccak-prg-vectors.json'), 'utf8')
);

// Drive a single (inject*; flip; extract*) vector against `createKeccakPrg`. Each `extract(n)`
// must byte-equal `expected[i]`. Vector schema is parallel arrays: `injects[]` is the list of
// pre-flip absorptions, `extracts[i]` is the byte count for the i'th post-flip extract call,
// `expected[i]` is the expected output bytes for that extract.
function driveVector(v) {
  const p = createKeccakPrg();
  for (const injectHex of v.injects) p.inject(fromHex0x(injectHex));
  p.flip();
  for (let i = 0; i < v.extracts.length; i++) {
    const got = p.extract(v.extracts[i]);
    const exp = fromHex0x(v.expected[i]);
    deepStrictEqual(got.length, v.extracts[i]);
    deepStrictEqual(bytesToHex(got), bytesToHex(exp));
  }
}

describe('Keccak-PRG', () => {
  // Layer 1 — canonical vectors transcribed from ZKNoxHQ/ETHDILITHIUM
  // test/keccak_prng.t.sol Solidity hex literals (the trust anchor that the upstream
  // `test_keccakPRNG` Solidity test asserts against on-chain).
  should('byte-identity over canonical (zhenfei) corpus', () => {
    const zhenfei = KECCAK_PRG_VECTORS.vectors.filter((v) => v.source === 'zhenfei-canonical');
    deepStrictEqual(zhenfei.length > 0, true);
    for (const v of zhenfei) driveVector(v);
  });

  // Layer 2 — boundary cases derived from ETHDILITHIUM's KeccakPRNG Python reference.
  // Covers multi-inject ordering, split-extract continuation, large-extract spanning multiple
  // keccak blocks, and per-call buffer-position persistence.
  should('byte-identity over python-ref-extended corpus', () => {
    const ext = KECCAK_PRG_VECTORS.vectors.filter((v) => v.source === 'python-ref-extended');
    deepStrictEqual(ext.length > 0, true);
    for (const v of ext) driveVector(v);
  });

  // Lifecycle invariants — fork-defined contract on the KeccakPrg API surface. No external
  // spec, no fixture; predicate matches on `.code` (the contract), not the message string
  // (implementation detail).
  should('lifecycle errors throw correct PrgLifecycleCode', () => {
    const isCode = (code) => (err) => err instanceof PrgLifecycleError && err.code === code;

    // extract before flip
    throws(() => createKeccakPrg().extract(1), isCode('PRG_EXTRACT_BEFORE_FLIP'));

    // double flip
    const p2 = createKeccakPrg();
    p2.flip();
    throws(() => p2.flip(), isCode('PRG_DOUBLE_FLIP'));

    // inject after flip
    const p3 = createKeccakPrg();
    p3.flip();
    throws(() => p3.inject(new Uint8Array([1])), isCode('PRG_INJECT_AFTER_FLIP'));

    // buffer overflow — KeccakPrg's pre-flip absorption buffer is 4096 B; one inject of 4097 B
    // overflows. Cumulative inject across multiple calls also overflows.
    const p4 = createKeccakPrg();
    throws(() => p4.inject(new Uint8Array(4097)), isCode('PRG_BUFFER_OVERFLOW'));

    const p5 = createKeccakPrg();
    p5.inject(new Uint8Array(4000));
    throws(() => p5.inject(new Uint8Array(97)), isCode('PRG_BUFFER_OVERFLOW'));
  });

  // Multi-inject semantics — pre-flip absorption is concatenative. Driving `inject(a) +
  // inject(b)` produces the same post-flip extract stream as `inject(a ‖ b)`. Validates that
  // the inject buffer is appended sequentially with no per-call boundary effect.
  should('multi-inject before flip equals concat-inject', () => {
    const a = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const b = new Uint8Array([9, 10, 11, 12, 13, 14, 15, 16]);

    const p1 = createKeccakPrg();
    p1.inject(a);
    p1.inject(b);
    p1.flip();
    const r1 = p1.extract(128);

    const p2 = createKeccakPrg();
    p2.inject(concatBytes(a, b));
    p2.flip();
    const r2 = p2.extract(128);

    deepStrictEqual(r1, r2);
  });

  // The constructor's `seed?` parameter is documented as equivalent to a separate inject call
  // before flip. Verify the equivalence is bit-perfect.
  should('createKeccakPrg(seed) shortcut equals separate inject(seed)', () => {
    const seed = new Uint8Array([7, 11, 13, 17, 19, 23, 29, 31, 37, 41]);

    const p1 = createKeccakPrg(seed);
    p1.flip();
    const r1 = p1.extract(96);

    const p2 = createKeccakPrg();
    p2.inject(seed);
    p2.flip();
    const r2 = p2.extract(96);

    deepStrictEqual(r1, r2);
  });

  // Split-extract should be byte-identical to one large extract — the output buffer position
  // persists across `extract` calls.
  should('split-extract equals single large extract', () => {
    const seed = new Uint8Array([42, 42, 42]);

    const p1 = createKeccakPrg();
    p1.inject(seed);
    p1.flip();
    const r1Big = p1.extract(200);

    const p2 = createKeccakPrg();
    p2.inject(seed);
    p2.flip();
    const r2Parts = concatBytes(p2.extract(7), p2.extract(53), p2.extract(140));

    deepStrictEqual(r1Big, r2Parts);
  });
});

should.runWhen(import.meta.url);
