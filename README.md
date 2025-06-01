# noble-curves-extended

This project extends [@noble/curves](https://github.com/paulmillr/noble-curves) to allow `randomBytes` to be specified externally. This is particularly useful for environments where you need to control the source of randomness, such as in testing or when using specific cryptographic hardware.

## Features

- External `randomBytes` function injection for all curves
- Support for multiple elliptic curves:
  - Ed25519 (EdDSA signatures)
  - NIST curves (P256, P384, P521)
  - secp256k1 (Bitcoin's curve)
  - BLS12-381

## Installation

```bash
npm install noble-curves-extended
```

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
- `createBls12381(randomBytes: RandomBytes)`: Creates BLS12-381 curve instance

Each curve instance provides the same API as its counterpart in `@noble/curves`.

## Security

This library is a thin wrapper around `@noble/curves` and inherits its security properties. The only modification is the ability to inject a custom `randomBytes` function.

## License

MIT
