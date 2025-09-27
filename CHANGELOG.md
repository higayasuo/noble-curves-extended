# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.6] - 2025-09-27

### Added

- Dedicated unified classes for all curves with explicit metadata (including `keyByteLength`): `Ed25519`, `P256`, `P384`, `P521`, `Secp256k1`, `X25519`

### Changed

- Stopped reading metadata from `curve.CURVE`; defined required metadata as class properties across all unified classes
- Unified Weierstrass APIs: `weierstrassToJwkPublickKey`, `weierstrassToJwkPrivateKey`, `weierstrassToRawPublicKey`, and `weierstrassToRawPrivateKey` now take `keyByteLength`, `curveName`, and (where applicable) `signatureAlgorithmName`
- Updated Weierstrass tests and Web Crypto usage to pass the new parameters
- Montgomery JWK/public key tests updated to use explicit `32`-byte constants and new function signatures; removed `curve.GuBytes.length` usages
- README updated to prefer dedicated unified classes (and retain factory functions as an option)

### Removed

- Removed `getWeierstrassCurveName` and `getWeierstrassSignatureAlgorithm` helpers and their tests

## [0.2.5] - 2025-09-22

### Added

- Added `kid` to `JwkPublicKey`
- Added `key_ops` to `JwkBase`

## [0.2.4] - 2025-06-30

### Changed

- Changed error logging from `console.error` to `console.log` when catching exceptions to improve readability by avoiding stack trace output

## [0.2.3] - 2025-06-26

### Changed

- Improved error messages in `toRawPublicKey` and `toRawPrivateKey` functions across all curve types (Weierstrass, Edwards, Montgomery):
  - Removed "Invalid JWK:" prefix from all error messages for cleaner output
  - Made error messages start with capital letters for better readability
  - Enhanced error messages to be more specific and informative
  - Added `getErrorMessage` utility usage for consistent error handling
  - Updated test expectations to match the new error message format
  - Simplified test structure for non-critical parameters while maintaining comprehensive coverage for key validation

## [0.2.2] - 2025-06-25

### Added

- Added `createEcdhCurve` export to unified factory index.ts

## [0.2.1] - 2025-06-25

### Changed

- Changed `curveName` parameter type to `string` in `createEcdhCurve` and `createSignatureCurve` factory functions

## [0.2.0] - 2025-06-24

### Added

- Added support for multiple Weierstrass curves in public key recovery compatibility tests (P-256, P-384, P-521, secp256k1)
- Added `ellipticCurveName` property to curve configurations for cleaner mapping to elliptic library
- Added `getEdwardsCurveName` function for dynamic Edwards curve name detection
- Added `getMontgomeryCurveName` function for dynamic Montgomery curve name detection
- Added comprehensive test coverage for curve name detection functions
- Added unified factory functions for creating signature and ECDH curves

### Changed

- **BREAKING**: Replaced `Ed25519` class with generic `Edwards` class that dynamically determines curve name
- **BREAKING**: Renamed `signatureAlgorithm` property to `signatureAlgorithmName` in `Signature` interface and related classes for naming consistency
- Refactored Montgomery curve utilities to use consistent naming (replaced `x25519` with `montgomery`)
- Updated all test files to use dynamic length checks based on `curve.GuBytes.length` for Montgomery curves
- Moved curve creation to top-level `describe` blocks in test files for better performance
- Reorganized unified curve utilities into separate directories for better maintainability
- Updated export lists to be alphabetically ordered and exclude test directories

### Fixed

- Fixed deprecation warnings in Vitest tests by replacing `it.skip.each()` with `it.each()`
- Fixed type errors with `curveName` property in Edwards curve implementations
- Fixed import paths and function names for consistency across the codebase
- Fixed test structure to use proper curve instantiation patterns

### Removed

- Removed Web Crypto API compatibility tests for public key recovery (not supported by Web Crypto API)
- Removed redundant test files and consolidated test structure

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
