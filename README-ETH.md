# noble-post-quantum — ETH variants

This fork adds two Ethereum-oriented signature schemes on top of upstream `@noble/post-quantum`:

- **`falcon512paddedEth`** — Falcon-512 padded with Keccak-256 counter-mode HashToPoint (byte-compatible with [ETHFALCON](https://github.com/ZKNoxHQ/ETHFALCON)).
- **`ml_dsa44eth`** — ML-DSA-44 (Dilithium-2) with Keccak-PRG replacing every SHAKE-128 / SHAKE-256 call-site (byte-compatible with [ETHDILITHIUM](https://github.com/ZKNoxHQ/ETHDILITHIUM)).

Both are designed to be consumed by the matching on-chain ZKNoxHQ Solidity verifiers (`ZKNOX_ethfalcon`, `ZKNOX_ethdilithium`). Wire-format encoders live under `@noble/post-quantum/utils-eth.js` and return `Uint8Array` — hex-wrap at the viem boundary with `bytesToHex`.

> **Experimental.** The ETH variants are not NIST-standardized. The audited ZKNox verifier contracts implement the matching on-chain algorithm; the off-chain implementation here tracks their Python reference.

## Install

Pin to this fork's `eth-variants` branch via a `git+ssh` URL in your consumer's `package.json`:

```json
{
  "devDependencies": {
    "@noble/post-quantum": "git+ssh://git@github.com/LimeChain/noble-post-quantum-eth.git#eth-variants"
  }
}
```

Then `npm install` resolves the branch tip and records the fetched SHA in `package-lock.json` as a drift guard.

**Branch ref vs SHA ref.** `#eth-variants` tracks the branch tip — subsequent `npm install` runs may pick up new commits. For a fully SHA-pinned, audit-stable pin (recommended once the fork stabilises), replace the ref with a commit SHA: `…#<40-hex-sha>`.

**Build step.** The fork publishes a `prepare` script that runs `tsc` after install, so the compiled `*.js` / `*.d.ts` artefacts the consumer imports are generated automatically by npm when it checks the branch out into `node_modules/`.

## Falcon-ETH — `falcon512paddedEth`

Falcon-512 padded with Keccak-256 counter-mode HashToPoint. Keygen / sign / verify behaviour is inherited from `falcon512padded`; only the HashToPoint binding differs.

End-to-end against an ERC-4337 account wired to `ZKNOX_ethfalcon`:

```ts
import { falcon512paddedEth } from '@noble/post-quantum/falcon.js';
import { encodeFalconPublicKey, encodeFalconSignature } from '@noble/post-quantum/utils-eth.js';
import { bytesToHex } from 'viem';

// 1. Keygen — raw NIST-encoded Falcon-512 keypair.
const { publicKey, secretKey } = falcon512paddedEth.keygen();
// publicKey: 897 B   secretKey: 1281 B

// 2. Encode pk for on-chain storage.
//    ZKNOX_ethfalcon.setKey() expects abi.encode(uint256[]) of 32 NTT-compact coefficients;
//    the verifier cannot run forward-NTT in its gas budget, so we pre-process off-chain.
const pkPayload = bytesToHex(encodeFalconPublicKey(publicKey)); // 1088 B hex

// 3. Register the key — verifier SSTORE2-writes and returns a 20-byte pointer blob.
const pointerBytes = await verifier.write.setKey([pkPayload]);

// 4. Sign a userOpHash — noble emits a 666 B detached signature (header ‖ salt ‖ compressed s2).
const nobleSig = falcon512paddedEth.sign(userOpHash, secretKey);

// 5. Encode signature for on-chain verification.
//    ZKNOX_falcon.verify() slices calldata as salt(40) ‖ s2_compact(1024) via calldataload
//    — raw concatenation, NOT ABI-encoded; the encoder decompresses s2 and repacks mod-Q big-endian.
userOp.signature = bytesToHex(encodeFalconSignature(nobleSig)); // 1064 B hex

// 6. Submit via the account's validateUserOp entrypoint.
await account.write.validateUserOp([userOp, userOpHash, 0n]);
```

Signing is randomised by default (`globalThis.crypto.getRandomValues`). For deterministic KAT replay, pass `opts.random` (custom byte generator — the signer consumes 40 B for the salt then 48 B for the FFSampler seed per call) or `opts.extraEntropy: Uint8Array(48)` (seeds an internal AES-CTR DRBG).

## ML-DSA-ETH — `ml_dsa44eth`

ML-DSA-44 (FIPS 204 Level 2, `k = l = 4`) with Keccak-PRG replacing every SHAKE-128 / SHAKE-256 call-site. Only parameter set the ETHDILITHIUM verifier supports.

End-to-end against an ERC-4337 account wired to `ZKNOX_ethdilithium`:

```ts
import { ml_dsa44eth } from '@noble/post-quantum/ml-dsa.js';
import { encodeMlDsaPublicKey, keccakXofFactory } from '@noble/post-quantum/utils-eth.js';
import { bytesToHex } from 'viem';

// 1. Keygen — raw NIST-encoded ML-DSA-44 keypair.
const { publicKey, secretKey } = ml_dsa44eth.keygen();
// publicKey: 1312 B   secretKey: 2560 B

// 2. Encode pk for on-chain storage.
//    ZKNOX_ethdilithium.setKey() expects abi.encode(bytes aHat, bytes tr, bytes t1)
//    with aHat already ExpandA-recovered and t1 already Power2Round-lifted + NTT-encoded
//    — the verifier skips ExpandA entirely and reads these pre-transformed forms directly.
//    Both XOF slots use Keccak-PRG for the ETH path (NIST path passes shake256XofFactory, shake128XofFactory).
const pkPayload = bytesToHex(encodeMlDsaPublicKey(publicKey, keccakXofFactory, keccakXofFactory));

// 3. Register the key — verifier SSTORE2-writes and returns a 20-byte pointer blob.
const pointerBytes = await verifier.write.setKey([pkPayload]);

// 4. Sign a userOpHash — noble emits a 2420 B signature (cTilde ‖ z ‖ h).
//    Output layout already matches the on-chain verifier's calldata expectations; no re-encoding.
const sig = ml_dsa44eth.sign(userOpHash, secretKey);
userOp.signature = bytesToHex(sig); // 2420 B hex

// 5. Submit via the account's validateUserOp entrypoint.
await account.write.validateUserOp([userOp, userOpHash, 0n]);
```

Signing is randomised by default (noble's `randomBytes` for the 32 B hedge). For deterministic KAT replay, pass `opts.extraEntropy: Uint8Array(32)` — the per-vector `rnd`.
