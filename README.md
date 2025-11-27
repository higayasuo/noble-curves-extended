# noble-curves-extended

This project extends [@noble/curves](https://github.com/paulmillr/noble-curves) to allow `randomBytes` to be specified externally. This is particularly useful for environments where you need to control the source of randomness, such as in testing or when using specific cryptographic hardware.

## Features

- External `randomBytes` function injection for all curves
- Support for multiple elliptic curves:
  - Ed25519 (EdDSA signatures)
  - NIST curves (P256, P384, P521)
  - secp256k1 (Bitcoin and Ethereum curve)
  - X25519 (ECDH key exchange)
  - BLS12-381 (Boneh-Lynn-Shacham signatures)
- Two-layer architecture: low-level curve operations and high-level unified API

## Installation

```bash
npm install noble-curves-extended
```

## Peer Dependencies

This package requires the following peer dependencies:

```bash
npm install @noble/curves @noble/hashes
```

These dependencies are required because this package is a thin wrapper around `@noble/curves` and uses `@noble/hashes` for cryptographic operations.

## Architecture

This library provides two layers of functionality:

### 1. Low-Level Curves (`@/curves`)

Direct curve implementations with external `randomBytes` injection. These provide the same API as `@noble/curves` but allow you to control the randomness source.

### 2. High-Level Unified API (`@/unified`)

A unified interface that abstracts curve differences and provides consistent APIs for different cryptographic operations (signatures, ECDH).

## Usage

### Low-Level Curves (`@/curves`)

```typescript
import {
  createEd25519,
  createSecp256k1,
  createP256,
  createP384,
  createP521,
  createX25519,
  createBls12_381,
} from 'noble-curves-extended';

// Create curve instances with your own randomBytes function
const ed25519 = createEd25519(randomBytes);
const secp256k1 = createSecp256k1(randomBytes);
const p256 = createP256(randomBytes);
const p384 = createP384(randomBytes);
const p521 = createP521(randomBytes);
const x25519 = createX25519(randomBytes);
const bls12_381 = createBls12_381(randomBytes);

// Use the curves as you would with @noble/curves
const privateKey = ed25519.utils.randomPrivateKey();
const publicKey = ed25519.getPublicKey(privateKey);
```

### High-Level Unified API (`@/unified`)

```typescript
import { Ed25519 } from 'noble-curves-extended';
import { P256, P384, P521, Secp256k1 } from 'noble-curves-extended';
import { X25519 } from 'noble-curves-extended';

// Create dedicated unified curve classes
const ed25519 = new Ed25519(randomBytes);
const p256 = new P256(randomBytes);
const p384 = new P384(randomBytes);
const p521 = new P521(randomBytes);
const secp256k1 = new Secp256k1(randomBytes);
const x25519 = new X25519(randomBytes);

// Use unified API for signatures
const privateKey = ed25519.randomPrivateKey();
const publicKey = ed25519.getPublicKey(privateKey);
const message = new TextEncoder().encode('Hello, World!');
const signature = ed25519.sign({ privateKey, message });
const isValid = ed25519.verify({ publicKey, message, signature });

// Use unified API for ECDH
const alicePrivateKey = x25519.randomPrivateKey();
const alicePublicKey = x25519.getPublicKey(alicePrivateKey);
const bobPrivateKey = x25519.randomPrivateKey();
const bobPublicKey = x25519.getPublicKey(bobPrivateKey);

const aliceSharedSecret = x25519.getSharedSecret({
  privateKey: alicePrivateKey,
  publicKey: bobPublicKey,
});
const bobSharedSecret = x25519.getSharedSecret({
  privateKey: bobPrivateKey,
  publicKey: alicePublicKey,
});
// aliceSharedSecret === bobSharedSecret

// JWK operations
const jwkPrivateKey = ed25519.toJwkPrivateKey(privateKey);
const jwkPublicKey = ed25519.toJwkPublicKey(publicKey);
const recoveredPrivateKey = ed25519.toRawPrivateKey(jwkPrivateKey);
const recoveredPublicKey = ed25519.toRawPublicKey(jwkPublicKey);
```

Alternatively, you can use factory functions when you want to obtain a curve by its name at runtime:

```typescript
import { createSignatureCurve, createEcdhCurve } from 'noble-curves-extended';

// Create by curve name (runtime)
const ed25519 = createSignatureCurve('Ed25519', randomBytes);
const p256 = createSignatureCurve('P-256', randomBytes);
const secp256k1 = createSignatureCurve('secp256k1', randomBytes);

const x25519 = createEcdhCurve('X25519', randomBytes);

// Use the same unified API
const privateKey = ed25519.randomPrivateKey();
const publicKey = ed25519.getPublicKey(privateKey);
const message = new TextEncoder().encode('Hello, World!');
const signature = ed25519.sign({ privateKey, message });
const isValid = ed25519.verify({ publicKey, message, signature });
```

### RNG-Disallowed Signature Curves

When you need to forbid RNG usage (e.g., to enforce deterministic behavior or harden code paths), use the RNG-disallowed factory. It returns a signature curve with RNG operations disabled while keeping signing/verification available.

```typescript
// Helper factory:
const curve = createSignatureCurveRngDisallowed('P-256');

// Example flow using the RNG-allowed factory to obtain a private key,
// then using the RNG-disallowed curve to sign/verify deterministically.
import {
  createSignatureCurve,
  createSignatureCurveRngDisallowed,
} from 'noble-curves-extended';
import { randomBytes } from '@noble/hashes/utils';

// Generate key material with RNG-allowed curve
const allowed = createSignatureCurve('P-256', randomBytes);

// Obtain an RNG-disallowed curve (no randomBytes/randomPrivateKey)
const noRng = createSignatureCurveRngDisallowed('P-256');

const privateKey = allowed.randomPrivateKey();
const publicKey = noRng.getPublicKey(privateKey, false);

// Deterministic sign (RFC 6979 for ECDSA; Ed25519 is deterministic by design)
const message = new TextEncoder().encode('Hello, RNG-free world!');
const signature = noRng.sign({ privateKey, message });
const ok = noRng.verify({ publicKey, message, signature });
```

## API

### RandomBytes Type

```typescript
type RandomBytes = (byteLength?: number) => Uint8Array;
```

### Low-Level Curves (`@/curves`)

#### Curve Creation Functions

- `createEd25519(randomBytes: RandomBytes)`: Creates Ed25519 curve instance
- `createSecp256k1(randomBytes: RandomBytes)`: Creates secp256k1 curve instance
- `createP256(randomBytes: RandomBytes)`: Creates NIST P256 curve instance
- `createP384(randomBytes: RandomBytes)`: Creates NIST P384 curve instance
- `createP521(randomBytes: RandomBytes)`: Creates NIST P521 curve instance
- `createX25519(randomBytes: RandomBytes)`: Creates X25519 curve instance
- `createBls12_381(randomBytes: RandomBytes)`: Creates BLS12-381 curve instance

Each curve instance provides the same API as its counterpart in `@noble/curves`.

### High-Level Unified API (`@/unified`)

#### Dedicated Classes

- `new Ed25519(randomBytes: RandomBytes)`
- `new P256(randomBytes: RandomBytes)`
- `new P384(randomBytes: RandomBytes)`
- `new P521(randomBytes: RandomBytes)`
- `new Secp256k1(randomBytes: RandomBytes)`
- `new X25519(randomBytes: RandomBytes)`

#### Factory Functions

- `createSignatureCurve(curveName: SignatureCurveName, randomBytes: RandomBytes)`
- `createEcdhCurve(curveName: EcdhCurveName, randomBytes: RandomBytes)`
- `createSignatureCurveRngDisallowed(curveName: SignatureCurveName)`

  Returns a signature curve with RNG operations disabled (randomBytes and randomPrivateKey are omitted). Signing remains available and deterministic (ECDSA uses RFC 6979; Ed25519 is deterministic by design).

#### Supported Unified Curves

Signature: `Ed25519`, `P-256`, `P-384`, `P-521`, `secp256k1`

ECDH: `P-256`, `P-384`, `P-521`, `secp256k1`, `X25519`

#### Unified Interface

All unified curve instances provide:

- `curveName: CurveName`: The name of the curve
- `keyByteLength: number`: The byte length of the key
- `randomPrivateKey(): Uint8Array`: Generate a random private key
- `getPublicKey(privateKey: Uint8Array, compressed?: boolean): Uint8Array`: Derive public key from private key
- `toJwkPrivateKey(privateKey: Uint8Array): JwkPrivateKey`: Convert private key to JWK format
- `toJwkPublicKey(publicKey: Uint8Array): JwkPublicKey`: Convert public key to JWK format
- `toRawPrivateKey(jwkPrivateKey: JwkPrivateKey): Uint8Array`: Convert JWK private key to raw format
- `toRawPublicKey(jwkPublicKey: JwkPublicKey): Uint8Array`: Convert JWK public key to raw format

#### Signature Curves Additional Methods

- `signatureAlgorithmName: SignatureAlgorithmName`: The signature algorithm name
- `sign({ privateKey, message, recovered? }): Uint8Array`: Sign a message
- `verify({ publicKey, message, signature }): boolean`: Verify a signature
- `recoverPublicKey({ signature, message, compressed? }): Uint8Array`: Recover public key from signature (Weierstrass curves only)

#### ECDH Curves Additional Methods

- `getSharedSecret({ privateKey, publicKey }): Uint8Array`: Compute shared secret

### Utilities

#### Curve Name Resolution

The library provides utility functions for resolving curve names from algorithm names or validating curve-algorithm pairs:

- `algorithmToCurveName(algorithmName: string): string`: Converts an algorithm name to its corresponding curve name. Supports `ES256` → `P-256`, `ES384` → `P-384`, `ES512` → `P-521`, and `ES256K` → `secp256k1`. Throws an error for unsupported algorithms.

- `resolveCurveName({ curveName?, algorithmName? }): string`: Resolves a curve name from either a curve name or an algorithm name. If both are provided, validates that they are consistent. If only `algorithmName` is provided, derives the curve name from it. If only `curveName` is provided, returns it as-is. Throws an error if neither is provided or if they don't match.

Example:

```typescript
import { algorithmToCurveName, resolveCurveName } from 'noble-curves-extended';

// Convert algorithm to curve name
const curveName = algorithmToCurveName('ES256'); // Returns 'P-256'

// Resolve curve name from algorithm
const resolved = resolveCurveName({ algorithmName: 'ES384' }); // Returns 'P-384'

// Resolve curve name from curve name
const resolved2 = resolveCurveName({ curveName: 'P-256' }); // Returns 'P-256'

// Validate consistency
const validated = resolveCurveName({
  curveName: 'P-256',
  algorithmName: 'ES256',
}); // Returns 'P-256' (validated)

// Throws error if mismatch
resolveCurveName({ curveName: 'P-256', algorithmName: 'ES384' }); // Throws error
```

#### Algorithm Name Resolution

The library provides utility functions for resolving algorithm names from curve names or validating algorithm-curve pairs:

- `curveToAlgorithmName(curveName: string): string | undefined`: Converts a curve name to its corresponding algorithm name. Supports `P-256` → `ES256`, `P-384` → `ES384`, `P-521` → `ES512`, `secp256k1` → `ES256K`, `Ed25519` → `EdDSA`, and `X25519` → `ES256K`. Returns `undefined` when the curve name cannot uniquely determine an algorithm name.

- `resolveAlgorithmName({ algorithmName?, curveName? }): string`: Resolves an algorithm name from either an algorithm name or a curve name. If both are provided, validates that they are consistent. If only `curveName` is provided, derives the algorithm name from it. If only `algorithmName` is provided, returns it as-is. Throws an error if neither is provided or if they don't match.

Example:

```typescript
import {
  curveToAlgorithmName,
  resolveAlgorithmName,
} from 'noble-curves-extended';

// Convert curve to algorithm name
const algorithmName = curveToAlgorithmName('P-256'); // Returns 'ES256'

// Resolve algorithm name from curve
const resolved = resolveAlgorithmName({ curveName: 'P-384' }); // Returns 'ES384'

// Resolve algorithm name from algorithm name
const resolved2 = resolveAlgorithmName({ algorithmName: 'ES256' }); // Returns 'ES256'

// Validate consistency
const validated = resolveAlgorithmName({
  algorithmName: 'ES256',
  curveName: 'P-256',
}); // Returns 'ES256' (validated)

// Throws error if mismatch
resolveAlgorithmName({ algorithmName: 'ES256', curveName: 'P-384' }); // Throws error
```

### BLS12-381 Specific

The BLS12-381 implementation provides:

- Custom random bytes generation through the `randomBytes` parameter
- Field operations over the BLS12-381 scalar field (Fr)
- Utility functions for key generation and management

## Security

This library is a thin wrapper around `@noble/curves` and inherits its security properties. The only modification is the ability to inject a custom `randomBytes` function.

## License

MIT
