# noble-curves-extended

This project extends [@noble/curves](https://github.com/paulmillr/noble-curves) to allow `randomBytes` to be specified externally. This is particularly useful for environments where you need to control the source of randomness, such as in testing or when using specific cryptographic hardware.

## Features

- External `randomBytes` function injection for all curves
- Support for multiple elliptic curves:
  - Ed25519 (EdDSA signatures)
  - NIST curves (P256, P384, P521)
  - secp256k1 (Bitcoin's curve)
  - BLS12-381 (Boneh-Lynn-Shacham signatures)

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

## Usage

```typescript
import {
  createEd25519,
  createSecp256k1,
  createP256,
  createP384,
  createP521,
  createBls12_381,
} from 'noble-curves-extended';

// Create curve instances with your own randomBytes function
const ed25519 = createEd25519(randomBytes);
const secp256k1 = createSecp256k1(randomBytes);
const p256 = createP256(randomBytes);
const p384 = createP384(randomBytes);
const p521 = createP521(randomBytes);
const bls12_381 = createBls12_381(randomBytes);

// Use the curves as you would with @noble/curves
const privateKey = ed25519.utils.randomPrivateKey();
const publicKey = ed25519.getPublicKey(privateKey);
```

## API

### RandomBytes Type

```typescript
type RandomBytes = (bytesLength?: number) => Uint8Array;
```

### Curve Creation Functions

- `createEd25519(randomBytes: RandomBytes)`: Creates Ed25519 curve instance
- `createSecp256k1(randomBytes: RandomBytes)`: Creates secp256k1 curve instance
- `createP256(randomBytes: RandomBytes)`: Creates NIST P256 curve instance
- `createP384(randomBytes: RandomBytes)`: Creates NIST P384 curve instance
- `createP521(randomBytes: RandomBytes)`: Creates NIST P521 curve instance
- `createBls12_381(randomBytes: RandomBytes)`: Creates BLS12-381 curve instance with custom random bytes generation

Each curve instance provides the same API as its counterpart in `@noble/curves`.

### BLS12-381 Specific

The BLS12-381 implementation provides:

- Custom random bytes generation through the `randomBytes` parameter
- Field operations over the BLS12-381 scalar field (Fr)
- Utility functions for key generation and management

### `createNistCurve(curveName: NistCurveName, randomBytes: RandomBytes)`

Creates a NIST curve instance by name. This function allows you to select one of the supported NIST curves (`'P-256'`, `'P-384'`, or `'P-521'`) at runtime and inject your own random bytes function.

**Parameters:**

- `curveName`: The name of the NIST curve to create. Must be one of `'P-256'`, `'P-384'`, or `'P-521'`.
- `randomBytes`: A function for generating cryptographically secure random bytes.

**Returns:**

- A curve instance with the same API as the corresponding `@noble/curves` curve, and the following additional properties:
  - `curveName`: The name of the curve.
  - `toJwkPublicKey(publicKey: Uint8Array): Jwk`: Converts a public key to a JWK object.
  - `toJwkPrivateKey(privateKey: Uint8Array): Jwk`: Converts a private key to a JWK object.
  - `toRawPublicKey(jwkPublicKey: Jwk): Uint8Array`: Converts a JWK public key to a raw uncompressed public key.
  - `toRawPrivateKey(jwkPrivateKey: Jwk): Uint8Array`: Converts a JWK private key to a raw private key.
  - `isValidPublicKey(publicKey: Uint8Array): boolean`: Validates if a given public key is a valid point on the curve.

**Additional Properties and Methods:**

- `curveName`: The name of the NIST curve instance (e.g., `'P-256'`, `'P-384'`, `'P-521'`).
- `randomBytes`: The random bytes function used for cryptographic operations.
- `toJwkPublicKey(publicKey: Uint8Array): Jwk`: Converts a raw public key to a JWK object.
- `toJwkPrivateKey(privateKey: Uint8Array): Jwk`: Converts a raw private key to a JWK object.
- `toRawPublicKey(jwkPublicKey: Jwk): Uint8Array`: Converts a JWK public key to a raw uncompressed public key (0x04 || x || y).
- `toRawPrivateKey(jwkPrivateKey: Jwk): Uint8Array`: Converts a JWK private key to a raw private key.
- `isValidPublicKey(publicKey: Uint8Array): boolean`: Checks if the provided public key is a valid point on the curve. Returns `true` if valid, otherwise `false`.

**Example:**

```typescript
import { createNistCurve } from 'noble-curves-extended';
import { randomBytes } from '@noble/hashes/utils';

const curveName = 'P-256';
const curve = createNistCurve(curveName, randomBytes);
const privateKey = curve.utils.randomPrivateKey();
const publicKey = curve.getPublicKey(privateKey);

// Convert to JWK
const jwkPub = curve.toJwkPublicKey(publicKey);
const jwkPriv = curve.toJwkPrivateKey(privateKey);

// Convert from JWK back to raw
const rawPub = curve.toRawPublicKey(jwkPub);
const rawPriv = curve.toRawPrivateKey(jwkPriv);

// Validate a public key
const isValid = curve.isValidPublicKey(publicKey); // true
const isValidInvalid = curve.isValidPublicKey(new Uint8Array([1, 2, 3])); // false

// Use with Web Crypto API
const importedPub = await crypto.subtle.importKey(
  'jwk',
  jwkPub,
  {
    name: 'ECDSA',
    namedCurve: curve.curveName,
  },
  true,
  ['verify'],
);
const importedPriv = await crypto.subtle.importKey(
  'jwk',
  jwkPriv,
  {
    name: 'ECDSA',
    namedCurve: curve.curveName,
  },
  true,
  ['sign'],
);
```

## Security

This library is a thin wrapper around `@noble/curves` and inherits its security properties. The only modification is the ability to inject a custom `randomBytes` function.

## License

MIT
