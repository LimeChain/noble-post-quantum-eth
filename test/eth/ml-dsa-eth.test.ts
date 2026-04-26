import { rngAesCtrDrbg256 } from '@noble/ciphers/aes.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, notDeepStrictEqual, throws } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ml_dsa44, ml_dsa44eth } from '../../src/ml-dsa.ts';
import {
  encodeMlDsaPublicKey,
  keccakXofFactory,
  shake128XofFactory,
  shake256XofFactory,
  type XofFactory,
} from '../../src/utils-eth.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Mirrors test/falcon.test.ts:24 — closure adapter over rngAesCtrDrbg256 to match the archived
// AES256_CTR_DRBG closure shape used by NIST PQCgenKAT corpora.
const aes256_ctr_drbg = (seed, personalization) => {
  const drbg = rngAesCtrDrbg256(seed, personalization);
  return (len, entropy) => drbg.randomBytes(len, entropy);
};

// Mirrors test/falcon.test.ts:28 — NIST .rsp parser. Blank-line-separated blocks of `key = hex`
// lines, group headers via leading `#`. Non-Dilithium2 groups (e.g. source-attribution headers)
// produce empty arrays which iterate as no-ops.
function parseKAT(path) {
  const lines = readFileSync(join(__dirname, path), 'utf8').trim().split('\n');
  const res = {};
  let test = null;
  let group = 'default';
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed === '') {
      if (test) {
        if (!res[group]) res[group] = [];
        res[group].push(test);
        test = null;
      }
      continue;
    }
    if (trimmed.startsWith('#')) {
      group = trimmed.slice(1).trim() || 'default';
      if (!res[group]) res[group] = [];
      continue;
    }
    const [k, v] = trimmed.split(/\s*=\s*/);
    if (!test) test = {};
    test[k] = v;
  }
  if (test) {
    if (!res[group]) res[group] = [];
    res[group].push(test);
  }
  return res;
}

const ETHDILITHIUM_KAT = parseKAT('./vectors/ml-dsa-44-eth-KAT.rsp');
const ENCODER_VECTORS = JSON.parse(
  readFileSync(join(__dirname, 'vectors/ml-dsa-encoder-vectors.json'), 'utf8')
);

const ML_DSA_44_SIG_BYTES = 2420;

describe('ML-DSA-ETH', () => {
  // For every .rsp row: derive (zeta, rnd) from the AES-CTR-DRBG seed via TWO separate
  // randomBytes(32) calls — NOT a single 64 B slice. The DRBG runs `__ctr_drbg_update` at the
  // end of every call (NIST SP 800-90A §10.2.1.5.1), so a 64 B draw produces a different second
  // half than two 32 B draws. ETHDILITHIUM's Python reference matches the two-call shape.
  //
  // ML-DSA's NIST PQCgenKAT `sm` field is `[sig(2420)][msg(mlen)]` — direct head slice gives
  // the 2420 B fixed signature; no length-prefix dance like Falcon's PQCgenKAT format.
  should('keygen + sign byte-identity over ETHDILITHIUM KAT', () => {
    for (const items of Object.values(ETHDILITHIUM_KAT)) {
      for (const t of items) {
        const drbg = aes256_ctr_drbg(hexToBytes(t.seed));
        const zeta = drbg(32);
        const rnd = drbg(32);

        const keys = ml_dsa44eth.keygen(zeta);
        deepStrictEqual(bytesToHex(keys.publicKey), t.pk.toLowerCase());
        deepStrictEqual(bytesToHex(keys.secretKey), t.sk.toLowerCase());
        deepStrictEqual(bytesToHex(ml_dsa44eth.getPublicKey(keys.secretKey)), t.pk.toLowerCase());

        const msg = hexToBytes(t.msg);
        const sig = ml_dsa44eth.sign(msg, keys.secretKey, { extraEntropy: rnd });
        deepStrictEqual(sig.length, ML_DSA_44_SIG_BYTES);

        const sm = hexToBytes(t.sm);
        const expectedSig = sm.subarray(0, ML_DSA_44_SIG_BYTES);
        deepStrictEqual(sig, expectedSig);

        deepStrictEqual(ml_dsa44eth.verify(sig, msg, keys.publicKey), true);
      }
    }
  });

  // Same 32 B zeta fed into both schemes. ML-DSA's keygen consumes the XOF surface (ExpandA →
  // matrix Â) which differs between SHAKE-128 and Keccak-PRG, so ALL of (pk, sk, sig) diverge —
  // stronger than Falcon-ETH where keygen was identical. Proves the fork's getMlDsaEth IIFE is
  // wired through keccakXofFactory rather than silently falling through to SHAKE.
  should('ml_dsa44eth diverges from ml_dsa44 under same seed', () => {
    const zeta = new Uint8Array(32).fill(7);
    const rnd = new Uint8Array(32).fill(11);
    const msg = new Uint8Array([1, 2, 3, 4]);

    const k1 = ml_dsa44.keygen(zeta);
    const k2 = ml_dsa44eth.keygen(zeta);
    notDeepStrictEqual(k1.publicKey, k2.publicKey);
    notDeepStrictEqual(k1.secretKey, k2.secretKey);

    const sig1 = ml_dsa44.sign(msg, k1.secretKey, { extraEntropy: rnd });
    const sig2 = ml_dsa44eth.sign(msg, k2.secretKey, { extraEntropy: rnd });
    notDeepStrictEqual(sig1, sig2);

    deepStrictEqual(ml_dsa44.verify(sig1, msg, k1.publicKey), true);
    deepStrictEqual(ml_dsa44eth.verify(sig2, msg, k2.publicKey), true);
    deepStrictEqual(ml_dsa44.verify(sig2, msg, k2.publicKey), false);
    deepStrictEqual(ml_dsa44eth.verify(sig1, msg, k1.publicKey), false);
  });

  // For each vector keyed by `count` to the .rsp corpus: keygen → encodeMlDsaPublicKey →
  // byte-equal the fixture's encoded payload. encodeMlDsaPublicKey emits the 3-tuple
  // `abi.encode(bytes aHatEncoded, bytes tr, bytes t1Encoded)` shape directly (no head-strip
  // dance; both sides emit the same wrapped form).
  should('encodeMlDsaPublicKey byte-identity (ETH path) vs ETHDILITHIUM reference', () => {
    const rspByCount = new Map();
    for (const items of Object.values(ETHDILITHIUM_KAT)) {
      for (const t of items) rspByCount.set(parseInt(t.count, 10), t);
    }
    for (const v of ENCODER_VECTORS.vectors) {
      const t = rspByCount.get(v.count);
      if (!t) throw new Error(`encoder vector count=${v.count} not found in KAT corpus`);
      const drbg = aes256_ctr_drbg(hexToBytes(t.seed));
      const zeta = drbg(32);
      const keys = ml_dsa44eth.keygen(zeta);
      const encoded = encodeMlDsaPublicKey(keys.publicKey, keccakXofFactory, keccakXofFactory);
      deepStrictEqual(bytesToHex(encoded), v.encodedPublicKey.slice(2).toLowerCase());
    }
  });

  // NIST path smoke check — `(shake256XofFactory, shake128XofFactory)` mirrors the Python
  // reference `_keygen_internal(_xof=<hash>, _xof2=<shake>)` split. Verifies the two-factory
  // contract works on both branches; not byte-identity vs an external reference (the NIST path
  // has no published Solidity verifier we can pin to).
  should('encodeMlDsaPublicKey shape on NIST path', () => {
    const zeta = new Uint8Array(32).fill(3);
    const { publicKey } = ml_dsa44.keygen(zeta);
    const encoded = encodeMlDsaPublicKey(publicKey, shake256XofFactory, shake128XofFactory);
    // Both ETH and NIST paths emit the same 3-tuple wrapper shape; fork's pythonref alignment
    // sets this length, so a simple sanity check on the byte count is sufficient.
    deepStrictEqual(encoded.length > 0, true);
    deepStrictEqual(encoded instanceof Uint8Array, true);
    // Decode the dynamic-tuple ABI head: 3 × 32 B offsets pointing into the tail.
    const headSize = 96;
    deepStrictEqual(encoded.length > headSize, true);
    const offset0 = Number(BigInt('0x' + bytesToHex(encoded.subarray(0, 32))));
    deepStrictEqual(offset0, headSize); // first dynamic tail starts immediately after the head
  });

  // The XOF factory adapters back the two-factory `encodeMlDsaPublicKey(rawPk, xofTr, xofExpandA)`
  // contract. Verify they each return a fresh XofReader per call (no cross-call state) and that
  // same seed → identical output, different seed → different output.
  should('XofFactory adapters return fresh readers per seed', () => {
    const factories: Array<[XofFactory, string]> = [
      [keccakXofFactory, 'keccak-prg'],
      [shake128XofFactory, 'shake128'],
      [shake256XofFactory, 'shake256'],
    ];
    const seedA = new Uint8Array(32).fill(0xaa);
    const seedB = new Uint8Array(32).fill(0xbb);
    for (const [factory, expectedId] of factories) {
      const r1 = factory(seedA);
      const r2 = factory(seedA);
      const r3 = factory(seedB);
      deepStrictEqual(r1.id, expectedId);
      deepStrictEqual(r2.id, expectedId);
      deepStrictEqual(r3.id, expectedId);
      // Two readers, same seed: identical sequence (no shared state leak).
      deepStrictEqual(r1.xof(64), r2.xof(64));
      // Different seed: different sequence.
      notDeepStrictEqual(r1.xof(64), r3.xof(64));
    }
  });

  // Mirrors upstream basic.test.ts ML-DSA api/shape patterns. ML-DSA-44 fixed sizes:
  // pk=1312, sk=2560, sig=2420, seed=32, signRand=32.
  should('api/shape', () => {
    const zeta = new Uint8Array(32).fill(1);
    const { publicKey, secretKey } = ml_dsa44eth.keygen(zeta);
    const sig = ml_dsa44eth.sign(new Uint8Array([1, 2, 3]), secretKey);
    deepStrictEqual(ml_dsa44eth.info.type, 'ml-dsa-eth');
    deepStrictEqual(ml_dsa44eth.lengths.seed, 32);
    deepStrictEqual(ml_dsa44eth.lengths.publicKey, 1312);
    deepStrictEqual(ml_dsa44eth.lengths.secretKey, 2560);
    deepStrictEqual(ml_dsa44eth.lengths.signRand, 32);
    deepStrictEqual(ml_dsa44eth.lengths.signature, 2420);
    deepStrictEqual(publicKey.length, 1312);
    deepStrictEqual(secretKey.length, 2560);
    deepStrictEqual(sig.length, 2420);
    deepStrictEqual(ml_dsa44eth.verify(sig, new Uint8Array([1, 2, 3]), publicKey), true);
  });

  should('keygen/validation', () => {
    ml_dsa44eth.keygen(new Uint8Array(32).fill(7));
    throws(() => ml_dsa44eth.keygen(new Uint8Array(0)));
    throws(() => ml_dsa44eth.keygen(new Uint8Array(1)));
    throws(() => ml_dsa44eth.keygen(new Uint8Array(31)));
    throws(() => ml_dsa44eth.keygen(new Uint8Array(33)));
  });

  should('sign/validation', () => {
    const zeta = new Uint8Array(32).fill(1);
    const { secretKey } = ml_dsa44eth.keygen(zeta);
    const msg = new Uint8Array([1, 2, 3]);
    const badMsgs = [undefined, 1, 'x', {}, []];
    for (const bad of badMsgs) {
      throws(() => ml_dsa44eth.sign(bad, secretKey));
    }
    const badRndLens = [0, 1, 31, 33, 64];
    for (const badLen of badRndLens) {
      throws(() => ml_dsa44eth.sign(msg, secretKey, { extraEntropy: new Uint8Array(badLen) }));
    }
    const badSks = [new Uint8Array(0), new Uint8Array(2559), new Uint8Array(2561)];
    for (const badSk of badSks) {
      throws(() => ml_dsa44eth.sign(msg, badSk));
    }
  });

  should('verify/validation', () => {
    const zeta = new Uint8Array(32).fill(1);
    const { publicKey, secretKey } = ml_dsa44eth.keygen(zeta);
    const msg = new Uint8Array([1, 2, 3]);
    const sig = ml_dsa44eth.sign(msg, secretKey);
    // ML-DSA's verify is permissive on the `sig` argument: non-Uint8Array values that read
    // as non-matching (numbers, strings, plain objects, arrays) return false rather than
    // throwing. Only `undefined` throws (no `.length` to read). The msg / pk slots throw on
    // any non-Uint8Array.
    throws(() => ml_dsa44eth.verify(undefined, msg, publicKey));
    const sigBads = [1, 'x', {}, []];
    for (const bad of sigBads) {
      deepStrictEqual(ml_dsa44eth.verify(bad, msg, publicKey), false);
    }
    const msgPkBads = [undefined, 1, 'x', {}, []];
    for (const bad of msgPkBads) {
      throws(() => ml_dsa44eth.verify(sig, bad, publicKey));
      throws(() => ml_dsa44eth.verify(sig, msg, bad));
    }
    // Wrong-length sig bytes — verify returns false (cryptographic reject), doesn't throw.
    deepStrictEqual(ml_dsa44eth.verify(new Uint8Array(2419), msg, publicKey), false);
    deepStrictEqual(ml_dsa44eth.verify(new Uint8Array(2421), msg, publicKey), false);
  });

  // Mirrors upstream basic.test.ts:80 Immutability/ML-DSA pattern. Input bytes (seed, sk) must
  // be unchanged after keygen/sign/getPublicKey calls.
  should('seed + sk immutability', () => {
    const zeta = new Uint8Array(32).fill(1);
    const zetaCopy = Uint8Array.from(zeta);
    const { secretKey } = ml_dsa44eth.keygen(zeta);
    deepStrictEqual(zeta, zetaCopy);

    const skCopy = Uint8Array.from(secretKey);
    const msg = new Uint8Array([1, 2, 3]);
    ml_dsa44eth.sign(msg, secretKey);
    deepStrictEqual(secretKey, skCopy);

    ml_dsa44eth.getPublicKey(secretKey);
    deepStrictEqual(secretKey, skCopy);
  });
});

should.runWhen(import.meta.url);
