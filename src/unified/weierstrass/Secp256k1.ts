import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { Weierstrass } from './Weierstrass';
import { RandomBytes } from '@/curves/types';

/**
 * secp256k1 curve implementation for digital signatures and ECDH.
 * This class provides a high-level interface for secp256k1 curve operations, including
 * key generation, validation, signing, verification, ECDH, and JWK/raw conversions.
 *
 * @example
 * ```typescript
 * const secp256k1 = new Secp256k1(randomBytes);
 * const privateKey = secp256k1.randomPrivateKey();
 * const publicKey = secp256k1.getPublicKey(privateKey);
 * const message = new TextEncoder().encode('hello');
 * const signature = secp256k1.sign({ message, privateKey });
 * const isValid = secp256k1.verify({ signature, message, publicKey });
 * ```
 */
export class Secp256k1 extends Weierstrass {
  /**
   * Creates a new secp256k1 curve instance.
   *
   * @param {RandomBytes} randomBytes - Function to generate random bytes
   */
  constructor(randomBytes: RandomBytes) {
    super({
      curve: createSecp256k1(randomBytes),
      randomBytes,
      curveName: 'secp256k1',
      signatureAlgorithmName: 'ES256K',
      keyByteLength: 32,
    });
  }
}
