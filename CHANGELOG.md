# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2025-06-13

### Added

- Added `isValidPublicKey` property to the `NistCurve` type returned by `createNistCurve` in `createNistCurve.ts`.
- The `isValidPublicKey` implementation is provided in `isValidPublicKey.ts` and allows validation of public keys as valid points on the curve.

## [0.1.3] - 2025-06-05

### Added

- Added `randomBytes` property to the `NistCurve` type returned by `createNistCurve` in `createNistCurve.ts`.
- Added `toRawPrivateKey` and `toRawPublicKey` properties to the `NistCurve` type returned by `createNistCurve` in `createNistCurve.ts`.
- Added utility functions for converting JWK keys back to raw format:
  - `toRawPrivateKey.ts`: Converts JWK private keys to raw private key format
  - `toRawPublicKey.ts`: Converts JWK public keys to raw uncompressed public key format

## [0.1.2] - 2025-06-05

### Added

- Added `curveName`, `toJwkPrivateKey`, and `toJwkPublicKey` properties to the `NistCurve` type returned by `createNistCurve` in `createNistCurve.ts`.

## [0.1.1] - 2025-06-05

### Added

- Added `createNistCurve` function in `nist.ts` to allow dynamic instantiation of NIST curves (P-256, P-384, P-521) with custom random bytes function.

## [0.1.0] - 2025-06-01

### Added

- Initial implementation of BLS12-381 curve with custom random bytes generation
- Field operations over the BLS12-381 scalar field (Fr)
- Utility functions for key generation and management
- Support for external `randomBytes` function injection for all curves
- Support for multiple elliptic curves:
  - Ed25519 (EdDSA signatures)
  - NIST curves (P256, P384, P521)
  - secp256k1 (Bitcoin's curve)
  - BLS12-381 (Boneh-Lynn-Shacham signatures)

### Changed

- Updated README.md with BLS12-381 specific documentation
- Fixed function name from `createBls12381` to `createBls12_381`

### Security

- This library is a thin wrapper around `@noble/curves` and inherits its security properties
- The only modification is the ability to inject a custom `randomBytes` function

## [Unreleased]
