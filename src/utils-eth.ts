/**
 * Ethereum-chain helpers for @noble/post-quantum.
 *
 * Houses the ETH-variant HashToPoint primitive and ZKNox wire-format
 * encoders consumed by `falcon512paddedEth` (exported from `./falcon.ts`).
 *
 * Strict DAG: this module imports only from `@noble/*` and `./_crystals.ts` —
 * never from sibling scheme modules. Scheme modules (`./falcon.ts`, and
 * future `./ml-dsa.ts` ETH-variants) import FROM this module, not vice
 * versa. No cyclic imports.
 *
 * Designed to hold ETH-side helpers for multiple PQC schemes. Falcon-ETH
 * is the day-one resident; ML-DSA-ETH will join with its own scheme-prefixed
 * encoders and XOF-factory primitives in a follow-up extraction.
 *
 * @module utils-eth
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { invert } from '@noble/curves/abstract/modular.js';
import { keccak_256 } from '@noble/hashes/sha3.js';

import { genCrystals } from './_crystals.ts';

// ===== Shared helpers (module-internal) ================================

/**
 * Write `values` as consecutive 32-byte big-endian uint256 words into `out`
 * starting at byte `offset`. Dedupes the compact-word pack loops used by
 * both `encodeFalconPublicKey` (inside the ABI envelope) and
 * `encodeFalconSignature` (raw, after the salt).
 */
function packBigEndianWords(
  values: bigint[],
  out: Uint8Array,
  offset: number,
): void {
  for (let i = 0; i < values.length; i++) {
    const word = values[i] as bigint;
    const wordOffset = offset + i * 32;
    for (let j = 0; j < 32; j++) {
      out[wordOffset + (31 - j)] = Number((word >> BigInt(8 * j)) & 0xffn);
    }
  }
}

/**
 * Produce the byte layout Solidity emits for top-level `abi.encode(uint256[])`:
 *   offset(32) ‖ length(32) ‖ N × 32B-BE-word.
 * Offset is always 32 (single dynamic head pointing at the start of data).
 */
function encodeUint256ArrayAbi(values: bigint[]): Uint8Array {
  const n = values.length;
  const out = new Uint8Array(32 + 32 + n * 32);
  // offset word [0..32): 32-byte BE encoding of the literal 32
  out[31] = 0x20;
  // length word [32..64): 32-byte BE encoding of n. setBigUint64 writes the
  // low 8 bytes at [56..64); the high 24 bytes stay zero (max safe n for
  // uint256[] is 2^32 elements, which already saturates u64)
  const lenView = new DataView(out.buffer, out.byteOffset, out.byteLength);
  lenView.setBigUint64(56, BigInt(n), false);
  packBigEndianWords(values, out, 64);
  return out;
}

/**
 * Pack `coeffs` (each ≤ m bits) into `coeffs.length * m / 256` uint256 words,
 * little-endian over the coefficient index within each word. Verbatim port of
 * the helper currently living at `mldsa-encoding.ts#compactPoly256` in the
 * ETHFALCON/ML-DSA consumer repo. When the ML-DSA-ETH extraction lands, the
 * repo's copy is removed and this becomes the sole source of truth.
 */
function compactPoly256(
  coeffs: ArrayLike<number | bigint>,
  m: number,
): bigint[] {
  if (m >= 256) throw new Error('compactPoly256: m must be less than 256');
  if ((coeffs.length * m) % 256 !== 0) {
    throw new Error('compactPoly256: total bits must be divisible by 256');
  }

  const a: bigint[] = new Array(coeffs.length);
  for (let i = 0; i < coeffs.length; i++) {
    const x = coeffs[i];
    if (x === undefined) throw new Error(`compactPoly256: undefined at ${i}`);
    const v = typeof x === 'bigint' ? x : BigInt(Math.floor(x));
    if (v >= 1n << BigInt(m)) {
      throw new Error(`compactPoly256: element ${v} too large for ${m} bits`);
    }
    a[i] = v;
  }

  const n = (a.length * m) / 256;
  const b = new Array<bigint>(n).fill(0n);
  for (let i = 0; i < a.length; i++) {
    const idx = Math.floor((i * m) / 256);
    const shift = BigInt((i % (256 / m)) * m);
    b[idx] = (b[idx] as bigint) | ((a[i] as bigint) << shift);
  }
  return b;
}

// ===== Falcon-512 shared constants (NIST + ETH variants) ===============

const FALCON_N = 512;
const FALCON_Q = 12289;
const FALCON_ROOT_OF_UNITY = 7;
// F = N^-1 mod Q, literal 12265 from ETHFALCON/src/ZKNOX_falcon_utils.sol:36
// (nm1modq). Loud assertion catches any upstream invert() drift.
const FALCON_F_INV = 12265;
if (FALCON_F_INV !== Number(invert(BigInt(FALCON_N), BigInt(FALCON_Q)))) {
  throw new Error(
    'Falcon-512 utils-eth: F_INV (nm1modq) drift — expected 12265 = invert(N, Q)',
  );
}
const falconCrystals = genCrystals({
  N: FALCON_N,
  Q: FALCON_Q,
  F: FALCON_F_INV,
  ROOT_OF_UNITY: FALCON_ROOT_OF_UNITY,
  newPoly: (n: number) => new Uint16Array(n),
  isKyber: false,
  brvBits: 10,
});

// pk layout: header(1) ‖ 512-coeff 14-bit-MSB packed body(896) = 897
const FALCON_PK_HEADER_BYTE = 0x09;
const FALCON_PK_BODY_BYTES = 896;
const FALCON_PK_BYTES = 1 + FALCON_PK_BODY_BYTES;

// sig layout: header(1) ‖ salt(40) ‖ Algorithm-17 compressed s2 (variable)
const FALCON_SIG_HEADER_BYTE = 0x39;
const FALCON_SALT_LEN = 40;
const FALCON_ALGO17_LIMIT = 2047;

// Compact encoding: 16 coefficients per uint256 word (≤14 bits padded to 16)
const FALCON_COMPACT_BITS = 16;
const FALCON_COMPACT_WORDS = (FALCON_N * FALCON_COMPACT_BITS) / 256; // 32
const FALCON_SIG_RAW_PAYLOAD_LEN = FALCON_SALT_LEN + FALCON_COMPACT_WORDS * 32; // 1064

// ===== Falcon-512 private helpers =======================================

/**
 * Unpack a 896-byte 14-bit-MSB-packed public-key body into 512 coefficients
 * in [0, Q). Mirrors `bitsCoderMSB(d=14).decode` from `./falcon.ts` without
 * reaching into noble's non-exported internals.
 */
function decodeFalconPublicKey14Bit(body: Uint8Array): Uint16Array {
  if (body.length !== FALCON_PK_BODY_BYTES) {
    throw new Error(
      `Falcon-512 pk body: expected ${FALCON_PK_BODY_BYTES} bytes, got ${body.length}`,
    );
  }
  const out = new Uint16Array(FALCON_N);
  let buf = 0;
  let bufLen = 0;
  let pos = 0;
  for (let i = 0; i < body.length; i++) {
    buf = (buf << 8) | body[i];
    bufLen += 8;
    if (bufLen >= 14) {
      bufLen -= 14;
      const v = (buf >>> bufLen) & 0x3fff;
      if (v >= FALCON_Q) throw new Error(`Falcon-512 pk coefficient ${pos}=${v} >= q`);
      out[pos++] = v;
      buf &= (1 << bufLen) - 1;
    }
  }
  if (pos !== FALCON_N) {
    throw new Error(`Falcon-512 pk: expected ${FALCON_N} coefficients, decoded ${pos}`);
  }
  return out;
}

/**
 * Decode Falcon's Algorithm 18 Golomb-Rice compressed s2 into 512 signed
 * coefficients in [-ALGO17_LIMIT, ALGO17_LIMIT]. Enforces negative-zero,
 * empty-accumulator, and zero-trailing-bits canonical-encoding checks to
 * match noble's verifier.
 */
function decompressFalconSignature(body: Uint8Array): Int16Array {
  const out = new Int16Array(FALCON_N);
  let buf = 0;
  let bufLen = 0;
  let pos = 0;

  const readBits = (n: number): number => {
    while (bufLen < n) {
      if (pos >= body.length) {
        throw new Error('Falcon-512 compressed s2: buffer underrun');
      }
      buf = (buf << 8) | body[pos++];
      bufLen += 8;
    }
    bufLen -= n;
    const val = (buf >>> bufLen) & ((1 << n) - 1);
    buf &= (1 << bufLen) - 1;
    return val;
  };

  for (let i = 0; i < FALCON_N; i++) {
    const sign = readBits(1);
    const low = readBits(7);
    let high = 0;
    while (readBits(1) === 0) {
      if (++high >= 16) {
        throw new Error('Falcon-512 compressed s2: runaway unary');
      }
    }
    const v = low | (high << 7);
    if (sign && v === 0) {
      throw new Error('Falcon-512 compressed s2: negative zero');
    }
    if (v > FALCON_ALGO17_LIMIT) {
      throw new Error(
        `Falcon-512 compressed s2: coeff ${v} > ${FALCON_ALGO17_LIMIT}`,
      );
    }
    out[i] = sign ? -v : v;
  }
  if (buf !== 0) {
    throw new Error('Falcon-512 compressed s2: non-zero accumulator');
  }
  for (let i = pos; i < body.length; i++) {
    if (body[i] !== 0) {
      throw new Error('Falcon-512 compressed s2: non-zero trailing byte');
    }
  }
  return out;
}

// ===== Falcon-512 public encoders =======================================

/**
 * Transform a raw 897-byte Falcon-512 NIST public key into the ABI-encoded
 * `uint256[]` bytes payload on-chain ZKNox-style verifiers ingest via
 * `abi.decode(data, (uint256[]))`. Produces 32 NTT-domain compacted
 * coefficients wrapped in the dynamic-array ABI envelope (1088 bytes total:
 * 32-byte offset + 32-byte length + 32 × 32-byte words).
 *
 * Shared across `falcon512`, `falcon512padded`, and `falcon512paddedEth` —
 * the pk-transform layer is invariant across Falcon variants (same
 * raw → forward-NTT → compact path).
 *
 * Port of `ETHFALCON/pythonref/sig_sol.py:31`:
 *   `pk_compact = falcon_compact(Poly(sk.h, q).ntt())`.
 */
export function encodeFalconPublicKey(rawPublicKey: Uint8Array): Uint8Array {
  if (rawPublicKey.length !== FALCON_PK_BYTES) {
    throw new Error(
      `Falcon-512 public key: expected ${FALCON_PK_BYTES} bytes, got ${rawPublicKey.length}`,
    );
  }
  if (rawPublicKey[0] !== FALCON_PK_HEADER_BYTE) {
    throw new Error(
      `Falcon-512 public key: expected header byte 0x${FALCON_PK_HEADER_BYTE.toString(16)}, ` +
      `got 0x${rawPublicKey[0].toString(16)}`,
    );
  }
  const h = decodeFalconPublicKey14Bit(rawPublicKey.subarray(1));
  falconCrystals.NTT.encode(h); // forward NTT, in-place; coeffs stay in [0, Q)
  const compact = compactPoly256(h, FALCON_COMPACT_BITS);
  if (compact.length !== FALCON_COMPACT_WORDS) {
    throw new Error(
      `Falcon-512 pk compact length mismatch: expected ${FALCON_COMPACT_WORDS}, got ${compact.length}`,
    );
  }
  return encodeUint256ArrayAbi(compact);
}

/**
 * Transform a noble detached Falcon-512 signature (header ‖ salt ‖
 * Algorithm-17 compressed s2) into the 1064-byte raw
 * `salt(40) ‖ s2_compact(1024)` payload expected by ZKNox-style on-chain
 * verifiers. NOT ABI-encoded — the Solidity verifier's assembly slices
 * `sig[0..40)` as salt and `sig[40..)` as 32 big-endian uint256 words via
 * `calldataload`, so no dynamic-array envelope is applied (see
 * `ETHFALCON/src/ZKNOX_falcon.sol:81-122`).
 *
 * Port of `ETHFALCON/pythonref/sig_sol.py:41-48`.
 */
export function encodeFalconSignature(nobleSig: Uint8Array): Uint8Array {
  if (nobleSig.length < 1 + FALCON_SALT_LEN + 1) {
    throw new Error(`Falcon-512 signature too short: ${nobleSig.length} bytes`);
  }
  if (nobleSig[0] !== FALCON_SIG_HEADER_BYTE) {
    throw new Error(
      `Falcon-512 signature: expected header byte 0x${FALCON_SIG_HEADER_BYTE.toString(16)}, ` +
      `got 0x${nobleSig[0].toString(16)}`,
    );
  }
  const salt = nobleSig.subarray(1, 1 + FALCON_SALT_LEN);
  const s2Signed = decompressFalconSignature(nobleSig.subarray(1 + FALCON_SALT_LEN));

  const s2ModQ = new Uint16Array(FALCON_N);
  for (let i = 0; i < FALCON_N; i++) {
    const v = s2Signed[i];
    s2ModQ[i] = v < 0 ? v + FALCON_Q : v;
  }
  const compact = compactPoly256(s2ModQ, FALCON_COMPACT_BITS);
  if (compact.length !== FALCON_COMPACT_WORDS) {
    throw new Error(
      `Falcon-512 sig compact length mismatch: expected ${FALCON_COMPACT_WORDS}, got ${compact.length}`,
    );
  }

  const out = new Uint8Array(FALCON_SIG_RAW_PAYLOAD_LEN);
  out.set(salt, 0);
  packBigEndianWords(compact, out, FALCON_SALT_LEN);
  return out;
}

// ===== Falcon-ETH HashToPoint (Keccak-256 counter mode) =================

const FALCON_ETH_STATE_SIZE = 32;
const FALCON_ETH_COUNTER_SIZE = 8;
const FALCON_ETH_EXTENDED_STATE_SIZE =
  FALCON_ETH_STATE_SIZE + FALCON_ETH_COUNTER_SIZE;
const FALCON_ETH_CHUNKS_PER_BUFFER = 16;
// Rejection threshold — exactly 5 * Q. Chunks ≥ KQ are discarded; chunks < KQ
// reduce mod Q. NOT 61440 — off-by-5 silently degrades uniformity on chunks
// in [61440, 61445).
const FALCON_ETH_KQ = 61445;

/**
 * Falcon-ETH variant HashToPoint — byte-identical to ETHFALCON's Solidity
 * free function `hashToPointEVM(salt, msgHash)` at
 * `ETHFALCON/src/ZKNOX_HashToPoint.sol:22-52`. Consumed by
 * `falcon512paddedEth` (exported from `./falcon.ts`) via the internal
 * `opts.hashToPoint?` seam inside `genFalcon`.
 *
 * Algorithm (Keccak-256 counter mode):
 *   1. state = keccak256(salt ‖ msg)                                 (32 B)
 *   2. extended = state ‖ counter_u64_be                             (40 B)
 *   3. Per outer iter: buffer = keccak256(extended)                  (32 B)
 *        For each of 16 BIG-ENDIAN 2-byte chunks, if chunk < KQ,
 *        append chunk % Q to output. Stop when 512 coefficients are
 *        accepted; otherwise increment the BE u64 counter in-place
 *        at extended[32..40) and re-hash.
 *
 * Load-bearing invariants:
 *   - Chunk endianness is BIG-ENDIAN: `(buf[2k] << 8) | buf[2k+1]`.
 *     NOT little-endian.
 *   - KQ = 61445 exactly (= 5 * Q). Not 61440.
 *   - `mod Q` applies AFTER the rejection gate — a chunk equal to Q is
 *     valid and reduces to 0 (preserves uniformity over Z_q).
 *   - First accepted chunk goes to `output[0]` (forward acceptance order).
 *   - `keccak256(extended)` is a ONE-SHOT hash per iteration, NOT a
 *     Keccak-PRG session (different primitive shape — do not conflate).
 *   - Counter lives as a u64 BIG-ENDIAN at bytes [32..40) of `extended`,
 *     incremented by 1 per outer iteration.
 *   - Absorb order is `salt ‖ msg` (NOT `msg ‖ salt` — that would be
 *     `hashToPointTETRATION`, a different algorithm).
 *
 * @param salt Salt bytes (typically 40 B for Falcon-512; length is not
 *             constrained by the algorithm).
 * @param msg  Message bytes (arbitrary length).
 * @returns    Uint16Array of length 512, every element < Q (= 12289).
 */
export function hashToPointEVM(
  salt: Uint8Array,
  msg: Uint8Array,
): Uint16Array {
  // --- Initial state: keccak256(salt ‖ msg) ---
  const concat = new Uint8Array(salt.length + msg.length);
  concat.set(salt, 0);
  concat.set(msg, salt.length);
  const initialState = keccak_256(concat);

  // --- Extended absorb buffer: state(32) ‖ counter_u64_be(8) ---
  const extendedState = new Uint8Array(FALCON_ETH_EXTENDED_STATE_SIZE);
  extendedState.set(initialState, 0);
  // Counter bytes [32..40) start at 0 (Uint8Array default). The DataView
  // below writes them as big-endian u64 as the counter advances.
  const extendedView = new DataView(
    extendedState.buffer,
    extendedState.byteOffset,
    extendedState.byteLength,
  );

  const output = new Uint16Array(FALCON_N);
  let i = 0;
  let counter = 0n;

  while (i < FALCON_N) {
    const buffer = keccak_256(extendedState);

    for (let chunkIdx = 0; chunkIdx < FALCON_ETH_CHUNKS_PER_BUFFER; chunkIdx++) {
      const byteOffset = chunkIdx * 2;
      const hi = buffer[byteOffset];
      const lo = buffer[byteOffset + 1];
      const chunk = (hi << 8) | lo;

      if (chunk < FALCON_ETH_KQ) {
        output[i] = chunk % FALCON_Q;
        i++;
        if (i === FALCON_N) break;
      }
    }

    counter += 1n;
    extendedView.setBigUint64(FALCON_ETH_STATE_SIZE, counter, false);
  }

  return output;
}
