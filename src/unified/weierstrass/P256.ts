import { createP256 } from '@/curves/weierstrass/p256';
import { Weierstrass } from './Weierstrass';
import { RandomBytes } from '@/curves/types';

/**
 * P-256 (secp256r1) curve implementation for digital signatures and ECDH.
 * This class provides a high-level interface for P-256 curve operations, including
 * key generation, validation, signing, verification, ECDH, and JWK/raw conversions.
 *
 * @example
 * ```typescript
 * const p256 = new P256(randomBytes);
 * const privateKey = p256.randomPrivateKey();
 * const publicKey = p256.getPublicKey(privateKey);
 * const message = new TextEncoder().encode('hello');
 * const signature = p256.sign({ message, privateKey });
 * const isValid = p256.verify({ signature, message, publicKey });
 * ```
 */
export class P256 extends Weierstrass {
  /**
   * Creates a new P-256 curve instance.
   *
   * @param {RandomBytes} randomBytes - Function to generate random bytes
   */
  constructor(randomBytes: RandomBytes) {
    super({
      curve: createP256(randomBytes),
      randomBytes,
      curveName: 'P-256',
      signatureAlgorithmName: 'ES256',
      keyByteLength: 32,
    });
  }
}
