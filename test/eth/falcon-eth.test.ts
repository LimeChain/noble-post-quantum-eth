import { rngAesCtrDrbg256 } from '@noble/ciphers/aes.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual, notDeepStrictEqual, throws } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as falcon from '../../src/falcon.ts';
import {
  encodeFalconPublicKey,
  encodeFalconSignature,
  hashToPointEVM,
} from '../../src/utils-eth.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Mirrors test/falcon.test.ts:24 — closure adapter over rngAesCtrDrbg256 to match the archived
// AES256_CTR_DRBG closure shape used by the NIST KAT corpus.
const aes256_ctr_drbg = (seed, personalization) => {
  const drbg = rngAesCtrDrbg256(seed, personalization);
  return (len, entropy) => drbg.randomBytes(len, entropy);
};

// Mirrors test/falcon.test.ts:28 — NIST .rsp parser. Blank-line-separated blocks of `key = hex`
// lines, group headers via leading `#`. Non-Falcon-512 groups (e.g. source-attribution headers)
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

const fromHex0x = (s) => hexToBytes(s.startsWith('0x') ? s.slice(2) : s);

const ETHFALCON_KAT = parseKAT('./vectors/falcon-eth-512-KAT.rsp');
const HASHTOPOINT_VECTORS = JSON.parse(
  readFileSync(join(__dirname, 'vectors/hashtopoint-vectors.json'), 'utf8')
);
const ENCODER_VECTORS = JSON.parse(
  readFileSync(join(__dirname, 'vectors/encoder-vectors.json'), 'utf8')
);

describe('Falcon-ETH', () => {
  // Cross-implementation byte-identity oracle against ETHFALCON's KAT corpus. The .rsp `sm`
  // field is in NIST PQCgenKAT attached form `[sigLen_be(2)][salt(40)][msg(mlen)][kernel_header
  // =0x29][body_variable]`; noble's padded detached output is `[round3_header=0x39][salt(40)]
  // [body_padded_to_625][padding=zeros]`. Wrappers differ but the salt + compressed body bytes
  // are identical between the two formats — both are produced by the same Keccak-HashToPoint
  // Falcon-512 signing flow consuming the same 88 B post-keygen DRBG draw (40 B salt + 48 B
  // FFSampler seed). Unpacking and comparing the inner bytes gives a 100-vector cross-impl
  // oracle that catches drift in HashToPoint, FFSampler, Algorithm-17 compression, and DRBG
  // advance order — strictly stronger than a self-consistent sign/verify roundtrip.
  should('sign byte-identity (unpacked) over ETHFALCON KAT', () => {
    for (const items of Object.values(ETHFALCON_KAT)) {
      for (const t of items) {
        const sm = hexToBytes(t.sm);
        const mlen = parseInt(t.mlen, 10);
        const sigLen = (sm[0] << 8) | sm[1]; // counts kernel_header(1) + body
        const expectedSalt = sm.subarray(2, 42);
        const bodyOffset = 42 + mlen + 1; // past 2B prefix + salt + msg + kernel_header
        const expectedBody = sm.subarray(bodyOffset, bodyOffset + sigLen - 1);

        const rng = aes256_ctr_drbg(hexToBytes(t.seed));
        const realSeed = rng(48);
        const keys = falcon.falcon512paddedEth.keygen(realSeed);
        deepStrictEqual(bytesToHex(keys.publicKey), t.pk.toLowerCase());
        deepStrictEqual(bytesToHex(keys.secretKey), t.sk.toLowerCase());

        const msg = hexToBytes(t.msg);
        const sig = falcon.falcon512paddedEth.sign(msg, keys.secretKey, { random: rng });
        // noble padded detached: [0x39][salt(40)][body_padded_625]
        deepStrictEqual(sig.length, 666);
        deepStrictEqual(sig[0], 0x39);
        deepStrictEqual(sig.subarray(1, 41), expectedSalt);
        deepStrictEqual(sig.subarray(41, 41 + expectedBody.length), expectedBody);
        // padding region must be all zeros
        const padding = sig.subarray(41 + expectedBody.length);
        deepStrictEqual(padding, new Uint8Array(padding.length));
        // sanity: the produced sig validates under our verify (uses our HashToPoint).
        deepStrictEqual(falcon.falcon512paddedEth.verify(sig, msg, keys.publicKey), true);
      }
    }
  });

  // Each vector pairs (salt, message) with a 512-coefficient expected polynomial captured from
  // the on-chain ZKNoxHQ free function `hashToPointEVM` (see vectors/hashtopoint-vectors.json
  // _source).
  should('hashToPointEVM byte-identity', () => {
    for (const v of HASHTOPOINT_VECTORS.vectors) {
      const salt = fromHex0x(v.salt);
      const message = fromHex0x(v.message);
      const got = hashToPointEVM(salt, message);
      deepStrictEqual(got.length, 512);
      deepStrictEqual(Array.from(got), v.expected);
      for (const c of got) {
        if (c >= 12289) throw new Error(`coefficient out of range: ${c} (q=12289)`);
      }
    }
  });

  // Same seed and same `random` callback fed into both schemes. Keygen is deterministic over
  // the seed, so secretKey and publicKey come out byte-identical. Signing diverges because the
  // hashToPoint binding swaps SHAKE-256 for Keccak-256 counter-mode — proves the injection at
  // src/falcon.ts actually rebinds the call rather than silently no-op'ing.
  should('falcon512paddedEth diverges from falcon512padded under same seed + random', () => {
    const seed = new Uint8Array(48).fill(7);
    const fixedRandom = (len = 0) => new Uint8Array(len).fill(11);

    const k1 = falcon.falcon512padded.keygen(seed);
    const k2 = falcon.falcon512paddedEth.keygen(seed);
    deepStrictEqual(k1.publicKey, k2.publicKey);
    deepStrictEqual(k1.secretKey, k2.secretKey);

    const msg = hexToBytes('48656c6c6f00');
    const padSig = falcon.falcon512padded.sign(msg, k1.secretKey, { random: fixedRandom });
    const ethSig = falcon.falcon512paddedEth.sign(msg, k2.secretKey, { random: fixedRandom });

    notDeepStrictEqual(padSig, ethSig);
    deepStrictEqual(falcon.falcon512padded.verify(padSig, msg, k1.publicKey), true);
    deepStrictEqual(falcon.falcon512paddedEth.verify(ethSig, msg, k2.publicKey), true);
    deepStrictEqual(falcon.falcon512padded.verify(ethSig, msg, k2.publicKey), false);
    deepStrictEqual(falcon.falcon512paddedEth.verify(padSig, msg, k1.publicKey), false);
  });

  // Cross-references encoder-vectors.json to the .rsp corpus by `count`, runs the same DRBG
  // advance pattern as the byte-identity test, and asserts:
  //   - encodeFalconPublicKey returns 1088 B (dynamic uint256[] ABI: 32 B offset + 32 B length
  //     + 1024 B body); body bytes match the 1024 B fixed `uint256[32]` reference from
  //     ETHFALCON's pythonref/sig_sol.py.
  //   - encodeFalconSignature returns the 1064 B raw `salt(40) ‖ s2_compact(1024)` byte-identical
  //     to the same reference output.
  should('encoder byte-identity from ETHFALCON sig_sol.py reference', () => {
    const rspByCount = new Map();
    for (const items of Object.values(ETHFALCON_KAT)) {
      for (const t of items) rspByCount.set(parseInt(t.count, 10), t);
    }
    for (const v of ENCODER_VECTORS.vectors) {
      const t = rspByCount.get(v.count);
      if (!t) throw new Error(`encoder vector count=${v.count} not found in KAT corpus`);
      const rng = aes256_ctr_drbg(hexToBytes(t.seed));
      const realSeed = rng(48);
      const keys = falcon.falcon512paddedEth.keygen(realSeed);
      const msg = hexToBytes(t.msg);

      const encodedPk = encodeFalconPublicKey(keys.publicKey);
      deepStrictEqual(encodedPk.length, 1088);
      deepStrictEqual(
        bytesToHex(encodedPk.subarray(64)),
        v.publicKeyCoefficientsAbi.slice(2).toLowerCase()
      );

      const rawSig = falcon.falcon512paddedEth.sign(msg, keys.secretKey, { random: rng });
      const encodedSig = encodeFalconSignature(rawSig);
      deepStrictEqual(encodedSig.length, 1064);
      deepStrictEqual(bytesToHex(encodedSig), v.encodedSignature.slice(2).toLowerCase());
    }
  });

  // Mirrors test/falcon.test.ts:594 (`api/shape` for falcon512padded) — fixed signature length
  // is 666 B for the 512 parameter set under the padded variant.
  should('api/shape', () => {
    const seed = new Uint8Array(48).fill(1);
    const { publicKey, secretKey } = falcon.falcon512paddedEth.keygen(seed);
    const sig = falcon.falcon512paddedEth.sign(new Uint8Array([1, 2, 3]), secretKey);
    deepStrictEqual(falcon.falcon512paddedEth.info.type, 'falcon');
    deepStrictEqual(falcon.falcon512paddedEth.lengths.seed, 48);
    deepStrictEqual(falcon.falcon512paddedEth.lengths.publicKey, publicKey.length);
    deepStrictEqual(falcon.falcon512paddedEth.lengths.secretKey, secretKey.length);
    deepStrictEqual(falcon.falcon512paddedEth.lengths.signRand, 48);
    deepStrictEqual(falcon.falcon512paddedEth.lengths.signature, sig.length);
    deepStrictEqual(falcon.falcon512paddedEth.attached.info.type, 'falcon');
    deepStrictEqual(falcon.falcon512paddedEth.attached.lengths.seed, 48);
    deepStrictEqual(falcon.falcon512paddedEth.attached.lengths.publicKey, publicKey.length);
    deepStrictEqual(falcon.falcon512paddedEth.attached.lengths.secretKey, secretKey.length);
    deepStrictEqual(falcon.falcon512paddedEth.attached.lengths.signRand, 48);
    deepStrictEqual(falcon.falcon512paddedEth.attached.getPublicKey(secretKey), publicKey);
    deepStrictEqual(
      falcon.falcon512paddedEth.verify(sig, new Uint8Array([1, 2, 3]), publicKey, {}),
      true
    );
    deepStrictEqual(
      falcon.falcon512paddedEth.verify(
        falcon.falcon512paddedEth.sign(new Uint8Array([1, 2, 3]), secretKey, {
          extraEntropy: false,
        }),
        new Uint8Array([1, 2, 3]),
        publicKey
      ),
      true
    );
    throws(() =>
      falcon.falcon512paddedEth.sign(new Uint8Array([1, 2, 3]), secretKey, {
        context: new Uint8Array([1]),
      })
    );
    throws(() =>
      falcon.falcon512paddedEth.verify(sig, new Uint8Array([1, 2, 3]), publicKey, {
        context: new Uint8Array([1]),
      })
    );
  });

  // Mirrors test/falcon.test.ts:473 — Round-3 KAT seeds are 48 B; reject anything else.
  should('keygen/validation', () => {
    falcon.falcon512paddedEth.keygen(new Uint8Array(48).fill(7));
    throws(() => falcon.falcon512paddedEth.keygen(new Uint8Array(0)));
    throws(() => falcon.falcon512paddedEth.keygen(new Uint8Array(1)));
    throws(() => falcon.falcon512paddedEth.keygen(new Uint8Array(47)));
    throws(() => falcon.falcon512paddedEth.keygen(new Uint8Array(49)));
  });

  // Mirrors test/falcon.test.ts:489 — wrong-typed messages must throw before any RNG draw,
  // and wrong-length nonce or seed must reject after the first RNG call.
  should('sign/validation', () => {
    const seed = new Uint8Array(48).fill(1);
    const { secretKey } = falcon.falcon512paddedEth.keygen(seed);
    const badMsgs = [undefined, 1, 'x', {}, []];
    for (const bad of badMsgs) {
      let calls = 0;
      const rnd = (len) => {
        calls++;
        return new Uint8Array(len).fill(calls);
      };
      throws(() => falcon.falcon512paddedEth.sign(bad, secretKey, { random: rnd }));
      deepStrictEqual(calls, 0);
      throws(() => falcon.falcon512paddedEth.attached.seal(bad, secretKey, { random: rnd }));
      deepStrictEqual(calls, 0);
    }
    const badNonceLens = [0, 1, 39, 41, 80];
    for (const badLen of badNonceLens) {
      let calls = 0;
      const rnd = (len) => {
        calls++;
        return new Uint8Array(calls === 1 ? badLen : len).fill(calls);
      };
      throws(() =>
        falcon.falcon512paddedEth.sign(new Uint8Array([1, 2, 3]), secretKey, { random: rnd })
      );
      calls = 0;
      throws(() =>
        falcon.falcon512paddedEth.attached.seal(new Uint8Array([1, 2, 3]), secretKey, {
          random: rnd,
        })
      );
    }
    const badSeedLens = [0, 1, 47, 49, 200];
    for (const badLen of badSeedLens) {
      let calls = 0;
      const rnd = (len) => {
        calls++;
        return new Uint8Array(calls === 1 ? len : badLen).fill(calls);
      };
      throws(() =>
        falcon.falcon512paddedEth.sign(new Uint8Array([1, 2, 3]), secretKey, { random: rnd })
      );
      calls = 0;
      throws(() =>
        falcon.falcon512paddedEth.attached.seal(new Uint8Array([1, 2, 3]), secretKey, {
          random: rnd,
        })
      );
    }
  });

  // Mirrors test/falcon.test.ts:533 — wrong-typed inputs throw rather than returning false,
  // matching the rest of the noble signer surface.
  should('verify/validation', () => {
    const seed = new Uint8Array(48).fill(1);
    const { publicKey, secretKey } = falcon.falcon512paddedEth.keygen(seed);
    const msg = new Uint8Array([1, 2, 3]);
    const sig = falcon.falcon512paddedEth.sign(msg, secretKey);
    const bads = [undefined, 1, 'x', {}, []];
    for (const bad of bads) {
      throws(() => falcon.falcon512paddedEth.verify(bad, msg, publicKey));
      throws(() => falcon.falcon512paddedEth.verify(sig, bad, publicKey));
      throws(() => falcon.falcon512paddedEth.verify(sig, msg, bad));
    }
  });
});

should.runWhen(import.meta.url);
