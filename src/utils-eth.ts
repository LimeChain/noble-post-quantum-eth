/**
 * Ethereum-chain helpers for @noble/post-quantum.
 *
 * Houses ETH-variant primitives and ZKNox wire-format encoders consumed by
 * the ETH scheme instances (`falcon512paddedEth` in `./falcon.ts`,
 * `ml_dsa44eth` in `./ml-dsa.ts`).
 *
 * Strict DAG: this module imports only from `@noble/*` and `./_crystals.ts` —
 * never from sibling scheme modules. Scheme modules (`./falcon.ts`,
 * `./ml-dsa.ts`) import FROM this module, not vice versa. No cyclic imports.
 *
 * Surface:
 * - ABI encoders: `encodeFalconPublicKey`, `encodeFalconSignature`,
 *   `encodeMlDsaPublicKey`.
 * - Falcon-ETH primitive: `hashToPointEVM` (Keccak-256 counter mode).
 * - XOF abstractions: `XofFactory`, `XofReader`, and the three factory
 *   adapters `shake128XofFactory`, `shake256XofFactory`, `keccakXofFactory`.
 * - Keccak-PRG primitive: `createKeccakPrg`, `KeccakPrg`, `PrgLifecycleError`,
 *   `PrgLifecycleCode` — byte-compatible with ZKNox's `Keccak256PRNG`.
 *
 * @module utils-eth
 */
/*! noble-post-quantum - MIT License (c) 2024 Paul Miller (paulmillr.com) */
import { invert } from '@noble/curves/abstract/modular.js';
import { keccak_256, shake128, shake256 } from '@noble/hashes/sha3.js';

import { genCrystals } from './_crystals.ts';

// ===== Shared helpers (module-internal) ================================

/**
 * Write `values` as consecutive 32-byte big-endian uint256 words into `out`
 * starting at byte `offset`. Dedupes the compact-word pack loops used by
 * both `encodeFalconPublicKey` (inside the ABI envelope) and
 * `encodeFalconSignature` (raw, after the salt).
 */
function packBigEndianWords(values: bigint[], out: Uint8Array, offset: number): void {
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
function compactPoly256(coeffs: ArrayLike<number | bigint>, m: number): bigint[] {
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

/**
 * Apply {@link compactPoly256} to every polynomial in a 2-D container.
 * Used by the ML-DSA public-key encoder to compact both the `A_hat` matrix
 * (K × L polys) and the transformed `t1` vector (1 × K polys, pre-transposed
 * by the caller into a single-row module) into 32-bit-per-coefficient
 * bigint words for the ZKNox on-chain verifier.
 */
function compactModule256(data: ArrayLike<ArrayLike<number | bigint>>[], m: number): bigint[][][] {
  const res: bigint[][][] = [];
  for (const row of data) {
    const inner: bigint[][] = [];
    for (let j = 0; j < row.length; j++) {
      const poly = row[j];
      if (poly === undefined) throw new Error(`compactModule256: undefined row at ${j}`);
      inner.push(compactPoly256(poly, m));
    }
    res.push(inner);
  }
  return res;
}

/**
 * Produce the byte layout Solidity emits for top-level `abi.encode(uint256[][])`:
 *   offset(32) ‖ length(32) ‖ [rowOffset]* ‖ [rowTail]*
 * where each `rowTail = length(32) ‖ [32B-BE word]*`. Row offsets are
 * relative to the start of the head (after this encoding's own length word).
 */
function encodeUint256MatrixAbi(data: bigint[][]): Uint8Array {
  const rows = data.length;
  const rowTails: Uint8Array[] = [];
  for (const row of data) {
    const t = new Uint8Array(32 + row.length * 32);
    const tView = new DataView(t.buffer, t.byteOffset, t.byteLength);
    tView.setBigUint64(24, BigInt(row.length), false);
    packBigEndianWords(row, t, 32);
    rowTails.push(t);
  }
  const headSize = rows * 32;
  const offsets: bigint[] = [];
  let acc = BigInt(headSize);
  for (const t of rowTails) {
    offsets.push(acc);
    acc += BigInt(t.length);
  }
  let tailSize = 0;
  for (const t of rowTails) tailSize += t.length;
  const out = new Uint8Array(32 + 32 + headSize + tailSize);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  out[31] = 0x20; // top-level offset word
  view.setBigUint64(32 + 24, BigInt(rows), false); // length
  for (let i = 0; i < rows; i++) {
    view.setBigUint64(32 + 32 + i * 32 + 24, offsets[i] as bigint, false);
  }
  let pos = 32 + 32 + headSize;
  for (const t of rowTails) {
    out.set(t, pos);
    pos += t.length;
  }
  return out;
}

/**
 * Produce the byte layout Solidity emits for top-level
 * `abi.encode(uint256[][][])`:
 *   offset(32) ‖ length(32) ‖ [matrixOffset]* ‖ [matrixTail]*
 * where each `matrixTail` is the inner `uint256[][]` encoding (no top-level
 * offset prefix). Matrix offsets are relative to the start of the head.
 */
function encodeUint256Module3Abi(data: bigint[][][]): Uint8Array {
  const matrices = data.length;
  const matrixTails: Uint8Array[] = [];
  for (const mat of data) {
    // Inner (no top-level offset): length(32) ‖ [rowOffset]* ‖ [rowTail]*
    const rows = mat.length;
    const rowTails: Uint8Array[] = [];
    for (const row of mat) {
      const t = new Uint8Array(32 + row.length * 32);
      const tView = new DataView(t.buffer, t.byteOffset, t.byteLength);
      tView.setBigUint64(24, BigInt(row.length), false);
      packBigEndianWords(row, t, 32);
      rowTails.push(t);
    }
    const innerHeadSize = rows * 32;
    const innerOffsets: bigint[] = [];
    let iacc = BigInt(innerHeadSize);
    for (const t of rowTails) {
      innerOffsets.push(iacc);
      iacc += BigInt(t.length);
    }
    let innerTailSize = 0;
    for (const t of rowTails) innerTailSize += t.length;
    const innerLen = 32 + innerHeadSize + innerTailSize;
    const inner = new Uint8Array(innerLen);
    const innerView = new DataView(inner.buffer, inner.byteOffset, inner.byteLength);
    innerView.setBigUint64(24, BigInt(rows), false);
    for (let i = 0; i < rows; i++) {
      innerView.setBigUint64(32 + i * 32 + 24, innerOffsets[i] as bigint, false);
    }
    let ipos = 32 + innerHeadSize;
    for (const t of rowTails) {
      inner.set(t, ipos);
      ipos += t.length;
    }
    matrixTails.push(inner);
  }
  const headSize = matrices * 32;
  const offsets: bigint[] = [];
  let acc = BigInt(headSize);
  for (const t of matrixTails) {
    offsets.push(acc);
    acc += BigInt(t.length);
  }
  let tailSize = 0;
  for (const t of matrixTails) tailSize += t.length;
  const out = new Uint8Array(32 + 32 + headSize + tailSize);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  out[31] = 0x20;
  view.setBigUint64(32 + 24, BigInt(matrices), false);
  for (let i = 0; i < matrices; i++) {
    view.setBigUint64(32 + 32 + i * 32 + 24, offsets[i] as bigint, false);
  }
  let pos = 32 + 32 + headSize;
  for (const t of matrixTails) {
    out.set(t, pos);
    pos += t.length;
  }
  return out;
}

/**
 * Produce the byte layout Solidity emits for top-level
 * `abi.encode(bytes, bytes, bytes)`:
 *   [offset0 offset1 offset2] ‖ [tail0 tail1 tail2]
 * where each tail is `length(32) ‖ data ‖ zero-padding-to-32B-multiple`.
 * The head is 3 × 32 bytes; offsets are relative to the start of the head.
 */
function encodeThreeBytesTupleAbi(a: Uint8Array, b: Uint8Array, c: Uint8Array): Uint8Array {
  const pad = (data: Uint8Array): Uint8Array => {
    const paddedLen = Math.ceil(data.length / 32) * 32;
    const t = new Uint8Array(32 + paddedLen);
    const view = new DataView(t.buffer, t.byteOffset, t.byteLength);
    view.setBigUint64(24, BigInt(data.length), false);
    t.set(data, 32);
    return t;
  };
  const parts = [pad(a), pad(b), pad(c)];
  const headSize = 96;
  const offsets = [
    BigInt(headSize),
    BigInt(headSize + parts[0]!.length),
    BigInt(headSize + parts[0]!.length + parts[1]!.length),
  ];
  const total = headSize + parts[0]!.length + parts[1]!.length + parts[2]!.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  for (let i = 0; i < 3; i++) {
    view.setBigUint64(i * 32 + 24, offsets[i] as bigint, false);
  }
  let pos = headSize;
  for (const p of parts) {
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}

// ===== XOF abstractions =================================================

/**
 * Stateful XOF reader produced by an {@link XofFactory}. Each `xof(length)`
 * call returns the next `length` bytes of the seeded stream; callers invoke
 * it repeatedly against a single reader (e.g. the ML-DSA ExpandA
 * rejection-sampling loop pulls multi-block chunks until 256 valid
 * coefficients accumulate).
 *
 * `id` is a named discriminant: shared test helpers such as
 * `assertBytesEqual` interpolate `(factory=<id>)` into divergence messages
 * so interleaved-factory regressions have a grep-friendly anchor.
 */
export interface XofReader {
  readonly id: 'shake128' | 'shake256' | 'keccak-prg';
  xof(length: number): Uint8Array;
}

/**
 * Constructs a fresh {@link XofReader} over `seed`. Every call MUST return
 * an independent reader — no cached state crosses invocations. This is the
 * parameterize-by-factory contract that supersedes module-level stateful
 * XOF instances; the ML-DSA-ETH fork at the bottom of `./ml-dsa.ts`
 * constructs fresh readers per sampler call.
 */
export type XofFactory = (seed: Uint8Array) => XofReader;

/** NIST ExpandA-role adapter: wraps `@noble/hashes/sha3#shake128`. */
export const shake128XofFactory: XofFactory = (seed) => {
  const h = shake128.create({}).update(seed);
  return {
    id: 'shake128',
    xof(length: number): Uint8Array {
      const buf = new Uint8Array(length);
      h.xofInto(buf);
      return buf;
    },
  };
};

/** NIST H/tr-role adapter: wraps `@noble/hashes/sha3#shake256`. */
export const shake256XofFactory: XofFactory = (seed) => {
  const h = shake256.create({}).update(seed);
  return {
    id: 'shake256',
    xof(length: number): Uint8Array {
      const buf = new Uint8Array(length);
      h.xofInto(buf);
      return buf;
    },
  };
};

/**
 * ETH single-XOF adapter: wraps {@link createKeccakPrg}. Collapses the
 * SHAKE-128 / SHAKE-256 split of the NIST path onto one Keccak-PRG
 * primitive — ETH callers populate both `xofFactory` and `xofFactory2`
 * parameters (e.g. of {@link encodeMlDsaPublicKey}) with this adapter.
 */
export const keccakXofFactory: XofFactory = (seed) => {
  const p = createKeccakPrg(seed);
  p.flip();
  return {
    id: 'keccak-prg',
    xof(length: number): Uint8Array {
      return p.extract(length);
    },
  };
};

// ===== Keccak-PRG primitive =============================================

/** Maximum cumulative inject size. Matches ZKNox Python ref. */
const KECCAK_PRG_MAX_BUFFER_SIZE = 4096;

/** Keccak-256 output size (bytes). */
const KECCAK_OUTPUT = 32;

/** Discriminant codes for {@link PrgLifecycleError}. Tests assert on `code`. */
export type PrgLifecycleCode =
  | 'PRG_INJECT_AFTER_FLIP'
  | 'PRG_EXTRACT_BEFORE_FLIP'
  | 'PRG_DOUBLE_FLIP'
  | 'PRG_BUFFER_OVERFLOW';

/**
 * Structured error thrown when the PRG state machine is driven out of
 * sequence or the inject buffer would overflow. Consumers discriminate
 * on `code` (never message text).
 */
export class PrgLifecycleError extends Error {
  readonly code: PrgLifecycleCode;

  constructor(message: string, code: PrgLifecycleCode, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PrgLifecycleError';
    this.code = code;
  }
}

/**
 * Keccak-PRG primitive surface. Instances are stateful — construct a
 * fresh one per caller. Never share instances across unrelated call
 * sites.
 */
export interface KeccakPrg {
  /** Absorb `data` into the buffer. Throws after `flip()`. */
  inject(data: Uint8Array): void;
  /** Finalize the state. One-shot — throws if called twice. */
  flip(): void;
  /** Stream `length` pseudorandom bytes. Throws before `flip()`. */
  extract(length: number): Uint8Array;
  /** SHAKE-parity alias for `inject`. */
  update(data: Uint8Array): void;
  /** SHAKE-parity alias for `extract`. */
  read(length: number): Uint8Array;
}

/**
 * Construct a fresh Keccak-PRG instance. Byte-compatible with ZKNox's
 * `Keccak256PRNG(a=None, b=None)` wrapper at
 * `ETHDILITHIUM/pythonref/dilithium_py/keccak_prng/keccak_prng_wrapper.py`.
 *
 * Three-phase one-way state machine:
 *   1. Absorb  — `inject(data)` appends to a 4096-byte internal buffer.
 *                Multiple calls concatenate. Disallowed after `flip()`.
 *   2. Flip    — `flip()` finalizes: `state = keccak256(buffer[:bufferLen])`.
 *                One-shot.
 *   3. Extract — `extract(n)` streams pseudorandom bytes by iterating
 *                `out_buffer = keccak256(state ‖ u64_be(counter))` and
 *                copying at most 32 bytes per iteration; partial blocks
 *                persist in `outBuffer[outBufferPos : outBufferLen]` so
 *                that `extract(5) + extract(27)` on one instance matches
 *                `extract(32)` on a freshly-seeded instance.
 *
 * Optional `seed` is equivalent to `const p = createKeccakPrg(); p.inject(seed);`
 * — it does NOT auto-flip. The caller must call `flip()` before any
 * `extract()`.
 */
export function createKeccakPrg(seed?: Uint8Array): KeccakPrg {
  const buffer = new Uint8Array(KECCAK_PRG_MAX_BUFFER_SIZE);
  let bufferLen = 0;
  let finalized = false;
  let state = new Uint8Array(KECCAK_OUTPUT);

  // Streaming output state.
  let outBuffer = new Uint8Array(KECCAK_OUTPUT);
  let outBufferPos = 0;
  let outBufferLen = 0;

  // bigint u64 counter — packed big-endian via DataView.setBigUint64 during
  // extract. Matches Python's arbitrary-precision int and Solidity's
  // `shl(192, counter)` MSB placement.
  let counter = 0n;

  // Scratch block for the extract hash: state(32) ‖ u64_be(counter)(8).
  const block = new Uint8Array(KECCAK_OUTPUT + 8);
  const blockView = new DataView(block.buffer);

  function inject(data: Uint8Array): void {
    if (finalized) {
      throw new PrgLifecycleError('Cannot inject after flip', 'PRG_INJECT_AFTER_FLIP');
    }
    if (bufferLen + data.length > KECCAK_PRG_MAX_BUFFER_SIZE) {
      throw new PrgLifecycleError(
        `Buffer overflow: ${bufferLen + data.length} > ${KECCAK_PRG_MAX_BUFFER_SIZE}`,
        'PRG_BUFFER_OVERFLOW'
      );
    }
    buffer.set(data, bufferLen);
    bufferLen += data.length;
  }

  function flip(): void {
    if (finalized) {
      throw new PrgLifecycleError('Already finalized', 'PRG_DOUBLE_FLIP');
    }
    // Single-shot hash of absorbed buffer. Empty-seed path: buffer[:0]
    // is the empty byte-string; keccak256(empty) is defined.
    state = keccak_256(buffer.subarray(0, bufferLen));
    finalized = true;
    outBufferPos = 0;
    outBufferLen = 0;
  }

  function extract(length: number): Uint8Array {
    if (!finalized) {
      throw new PrgLifecycleError(
        'PRG not finalized; call flip() before extract()',
        'PRG_EXTRACT_BEFORE_FLIP'
      );
    }

    const output = new Uint8Array(length);
    let offset = 0;

    // (1) Drain any leftover bytes from the previous extract call. This is
    //     load-bearing: extract(5) then extract(27) must NOT advance the
    //     counter — they read bytes [0..5) and [5..32) of the same block.
    if (outBufferLen > outBufferPos) {
      const available = outBufferLen - outBufferPos;
      const toCopy = Math.min(length, available);
      output.set(outBuffer.subarray(outBufferPos, outBufferPos + toCopy), 0);
      outBufferPos += toCopy;
      offset += toCopy;
      if (offset === length) return output;
    }

    // (2) Generate fresh blocks until the request is satisfied. Counter
    //     packed big-endian as u64 into bytes [32..40) of the block.
    while (offset < length) {
      block.set(state, 0);
      blockView.setBigUint64(KECCAK_OUTPUT, counter, false); // false = big-endian
      outBuffer = keccak_256(block);
      outBufferLen = KECCAK_OUTPUT;
      outBufferPos = 0;

      const remaining = length - offset;
      const toCopy = Math.min(remaining, KECCAK_OUTPUT);
      output.set(outBuffer.subarray(0, toCopy), offset);
      outBufferPos = toCopy;
      offset += toCopy;

      counter += 1n;
    }

    return output;
  }

  function update(data: Uint8Array): void {
    inject(data);
  }
  function read(length: number): Uint8Array {
    return extract(length);
  }

  // Optional ctor seed ≡ immediate inject.
  if (seed !== undefined && seed.length > 0) {
    inject(seed);
  }

  return { inject, flip, extract, update, read };
}

// ===== Falcon-512 shared constants (NIST + ETH variants) ===============

const FALCON_N = 512;
const FALCON_Q = 12289;
const FALCON_ROOT_OF_UNITY = 7;
// F = N^-1 mod Q, literal 12265 from ETHFALCON/src/ZKNOX_falcon_utils.sol:36
// (nm1modq). Loud assertion catches any upstream invert() drift.
const FALCON_F_INV = 12265;
if (FALCON_F_INV !== Number(invert(BigInt(FALCON_N), BigInt(FALCON_Q)))) {
  throw new Error('Falcon-512 utils-eth: F_INV (nm1modq) drift — expected 12265 = invert(N, Q)');
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
      `Falcon-512 pk body: expected ${FALCON_PK_BODY_BYTES} bytes, got ${body.length}`
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
      throw new Error(`Falcon-512 compressed s2: coeff ${v} > ${FALCON_ALGO17_LIMIT}`);
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
      `Falcon-512 public key: expected ${FALCON_PK_BYTES} bytes, got ${rawPublicKey.length}`
    );
  }
  if (rawPublicKey[0] !== FALCON_PK_HEADER_BYTE) {
    throw new Error(
      `Falcon-512 public key: expected header byte 0x${FALCON_PK_HEADER_BYTE.toString(16)}, ` +
        `got 0x${rawPublicKey[0].toString(16)}`
    );
  }
  const h = decodeFalconPublicKey14Bit(rawPublicKey.subarray(1));
  falconCrystals.NTT.encode(h); // forward NTT, in-place; coeffs stay in [0, Q)
  const compact = compactPoly256(h, FALCON_COMPACT_BITS);
  if (compact.length !== FALCON_COMPACT_WORDS) {
    throw new Error(
      `Falcon-512 pk compact length mismatch: expected ${FALCON_COMPACT_WORDS}, got ${compact.length}`
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
        `got 0x${nobleSig[0].toString(16)}`
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
      `Falcon-512 sig compact length mismatch: expected ${FALCON_COMPACT_WORDS}, got ${compact.length}`
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
const FALCON_ETH_EXTENDED_STATE_SIZE = FALCON_ETH_STATE_SIZE + FALCON_ETH_COUNTER_SIZE;
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
export function hashToPointEVM(salt: Uint8Array, msg: Uint8Array): Uint16Array {
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
    extendedState.byteLength
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

// ===== ML-DSA (shared NIST + ETH encoding) ==============================

// ML-DSA-44 (FIPS 204 Level 2) constants. ZKNox's `ZKNOX_dilithium` hard-codes
// `k = l = 4` at `ETHDILITHIUM/src/ZKNOX_dilithium_utils.sol:44-45`; no other
// parameter set has an on-chain verifier in the repo's scope.
const MLDSA_N = 256;
const MLDSA_Q = 8380417;
const MLDSA_K = 4;
const MLDSA_L = 4;
const MLDSA_D = 13; // FIPS 204 Table 1: dropped low bits in Power2Round
const MLDSA_RHO_BYTES = 32;
const MLDSA_T1_POLY_BYTES = 320; // 256 coeffs × 10 bits = 2560 bits → 320 B
const MLDSA_TR_BYTES = 64;
const MLDSA_PUBLIC_KEY_BYTES = MLDSA_RHO_BYTES + MLDSA_K * MLDSA_T1_POLY_BYTES; // 1312
const MLDSA_COMPACT_BITS = 32;
const MLDSA_F_INV = 8347681; // 256^-1 mod Q

// Independent crystals context for the public-key encoder's `transformT1Poly`
// forward-NTT. The fork's sibling `./ml-dsa.ts` has its OWN crystals
// instance; duplicating it here keeps this module's DAG invariant (leaf,
// imports only from `./_crystals.ts`). Both contexts use identical
// parameters (N=256, Q=8380417, F=8347681, ROOT=1753, Int32Array polys,
// brvBits=8) so their NTT outputs are byte-equal.
const mldsaCrystals = genCrystals({
  N: MLDSA_N,
  Q: MLDSA_Q,
  F: MLDSA_F_INV,
  ROOT_OF_UNITY: 1753,
  newPoly: (n: number) => new Int32Array(n),
  isKyber: false,
  brvBits: 8,
});

/** Decoded public-key components returned by {@link decodeMlDsaPublicKey}. */
interface DecodedMlDsaPublicKey {
  rho: Uint8Array;
  t1: number[][];
  tr: Uint8Array;
}

/**
 * Rejection-sample one 256-coefficient polynomial for ExpandA from the XOF
 * stream. Each accepted coefficient is a 23-bit integer < Q. Matches
 * noble's `RejNTTPoly` inner loop (ml-dsa.ts:199) — only the byte source
 * differs (flat-sequential `XofReader` here vs `XOF128.get(x,y)()` in noble).
 */
function mldsaRejectionSamplePoly(reader: XofReader): number[] {
  const r = new Array<number>(MLDSA_N).fill(0);
  let idx = 0;
  while (idx < MLDSA_N) {
    const buf = reader.xof(3 * 64);
    for (let k = 0; idx < MLDSA_N && k <= buf.length - 3; k += 3) {
      const b0 = buf[k];
      const b1 = buf[k + 1];
      const b2 = buf[k + 2];
      if (b0 === undefined || b1 === undefined || b2 === undefined) break;
      let t = b0 | (b1 << 8) | (b2 << 16);
      t &= 0x7fffff;
      if (t < MLDSA_Q) r[idx++] = t;
    }
  }
  return r;
}

/**
 * Rebuild the K×L `A_hat` matrix from `rho` by re-running ExpandA. Each
 * `A_hat[i][j]` is sampled from a fresh XOF over `rho ‖ u8(j) ‖ u8(i)`,
 * mirroring FIPS 204 Algorithm 32 (`rho ‖ IntegerToBytes(j, 1) ‖
 * IntegerToBytes(i, 1)`).
 */
function recoverMlDsaAhat(
  rho: Uint8Array,
  k: number,
  l: number,
  xofFactoryExpandA: XofFactory
): number[][][] {
  const aHat: number[][][] = [];
  for (let i = 0; i < k; i++) {
    const row: number[][] = [];
    for (let j = 0; j < l; j++) {
      const seed = new Uint8Array(rho.length + 2);
      seed.set(rho, 0);
      seed[rho.length] = j;
      seed[rho.length + 1] = i;
      row.push(mldsaRejectionSamplePoly(xofFactoryExpandA(seed)));
    }
    aHat.push(row);
  }
  return aHat;
}

/**
 * Unpack 320 bytes of 10-bit-packed `t1` coefficients into a length-256
 * polynomial (T1Coder.decode, port of noble's `polyCoder(10)`). Uses a
 * bigint accumulator so the 2560-bit chunk can be indexed with a single
 * mask per coefficient without worrying about JS number precision.
 */
function mldsaPolyDecode10Bits(bytes: Uint8Array): number[] {
  const poly = new Array<number>(MLDSA_N).fill(0);
  let r = 0n;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === undefined) break;
    r |= BigInt(b) << BigInt(8 * i);
  }
  const mask = (1n << 10n) - 1n;
  for (let i = 0; i < MLDSA_N; i++) {
    poly[i] = Number((r >> BigInt(i * 10)) & mask);
  }
  return poly;
}

/**
 * Parse a raw 1312-byte ML-DSA-44 NIST public key into `(rho, t1, tr)`.
 * `tr` is computed as `xofFactoryH(pk).xof(64)` — SHAKE-256 on the NIST
 * path, Keccak-PRG on the ETH path.
 */
function decodeMlDsaPublicKey(
  publicKey: Uint8Array,
  xofFactoryH: XofFactory
): DecodedMlDsaPublicKey {
  if (publicKey.length !== MLDSA_PUBLIC_KEY_BYTES) {
    throw new Error(
      `ML-DSA-44 public key: expected ${MLDSA_PUBLIC_KEY_BYTES} bytes, got ${publicKey.length}`
    );
  }
  const rho = publicKey.slice(0, MLDSA_RHO_BYTES);
  const t1: number[][] = [];
  for (let i = 0; i < MLDSA_K; i++) {
    const offset = MLDSA_RHO_BYTES + i * MLDSA_T1_POLY_BYTES;
    t1.push(mldsaPolyDecode10Bits(publicKey.slice(offset, offset + MLDSA_T1_POLY_BYTES)));
  }
  const tr = xofFactoryH(new Uint8Array(publicKey)).xof(MLDSA_TR_BYTES);
  return { rho, t1, tr };
}

/**
 * Apply the FIPS 204 verifier transform to one `t1` polynomial: shift each
 * coefficient by `2^d` (Power2Round high-bit lift) then forward NTT,
 * leaving coefficients mod Q. ZKNox's `ZKNOX_dilithium_core.sol#dilithiumCore2`
 * uses these pre-computed values directly when fusing `A*z - c*t1`
 * (ETHDILITHIUM line 199), and the on-chain test vectors at
 * `ETHDILITHIUM/test/dilithium.t.sol:543+` confirm storage in this
 * transformed form (values up to ~2^23 ≫ 2^10).
 */
function mldsaTransformT1Poly(poly: number[]): number[] {
  const buf = new Int32Array(MLDSA_N);
  for (let i = 0; i < MLDSA_N; i++) {
    const v = poly[i];
    if (v === undefined) throw new Error(`mldsaTransformT1Poly: undefined at ${i}`);
    buf[i] = v << MLDSA_D;
  }
  mldsaCrystals.NTT.encode(buf);
  const out = new Array<number>(MLDSA_N);
  for (let i = 0; i < MLDSA_N; i++) {
    const v = (buf[i] as number) % MLDSA_Q;
    out[i] = v >= 0 ? v : v + MLDSA_Q;
  }
  return out;
}

/**
 * Transform a raw 1312-byte ML-DSA-44 NIST public key into the ABI-encoded
 * `(bytes aHatEncoded, bytes tr, bytes t1Encoded)` payload that
 * `ZKNOX_dilithium.setKey()` writes via SSTORE2 and `_readPubKey` decodes
 * (`ETHDILITHIUM/src/ZKNOX_dilithium.sol:91-97`).
 *
 * Two-factory signature — matches the Python reference
 * `_keygen_internal(_xof=shake256, _xof2=shake128)` split:
 *
 * - `xofFactory`  ≡ Python `_xof`  — drives the `tr` H-of-pk computation
 *   (SHAKE-256 on the NIST path; Keccak-PRG on the ETH path).
 * - `xofFactory2` ≡ Python `_xof2` — drives ExpandA / rejection sampling
 *   (SHAKE-128 on the NIST path; Keccak-PRG on the ETH path).
 *
 * NIST callers pass `(shake256XofFactory, shake128XofFactory)`. ETH callers
 * pass `(keccakXofFactory, keccakXofFactory)` — same factory twice (the
 * single-primitive collapse for the ETH path).
 */
export function encodeMlDsaPublicKey(
  rawPublicKey: Uint8Array,
  xofFactory: XofFactory,
  xofFactory2: XofFactory
): Uint8Array {
  const { rho, t1, tr } = decodeMlDsaPublicKey(rawPublicKey, xofFactory);
  const aHat = recoverMlDsaAhat(rho, MLDSA_K, MLDSA_L, xofFactory2);
  const t1Transformed = t1.map(mldsaTransformT1Poly);

  const aHatCompact = compactModule256(aHat, MLDSA_COMPACT_BITS);
  const t1Transposed = [t1Transformed];
  const t1Compact = compactModule256(t1Transposed, MLDSA_COMPACT_BITS)[0];
  if (t1Compact === undefined) {
    throw new Error('encodeMlDsaPublicKey: t1Compact undefined');
  }

  const aHatEncoded = encodeUint256Module3Abi(aHatCompact);
  const t1Encoded = encodeUint256MatrixAbi(t1Compact);
  return encodeThreeBytesTupleAbi(aHatEncoded, tr, t1Encoded);
}
