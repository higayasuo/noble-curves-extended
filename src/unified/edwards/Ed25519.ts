import { Edwards } from './Edwards';
import { RandomBytes } from '@/curves/types';
import { createEd25519 } from '@/curves/edwards/ed25519';

/**
 * Ed25519 implementation for digital signatures.
 * This class provides a specialized Edwards curve implementation for Ed25519,
 * extending the base Edwards class with Ed25519-specific parameters.
 *
 * @example
 * ```typescript
 * import { randomBytes } from '@noble/hashes/utils';
 *
 * const ed25519 = new Ed25519(randomBytes);
 * const privateKey = ed25519.randomPrivateKey();
 * const publicKey = ed25519.getPublicKey(privateKey);
 * const message = new TextEncoder().encode('hello');
 * const signature = ed25519.sign({ message, privateKey });
 * const isValid = ed25519.verify({ signature, message, publicKey });
 * ```
 */
export class Ed25519 extends Edwards {
  /**
   * Creates a new Ed25519 instance.
   *
   * @param {RandomBytes} randomBytes - Function to generate random bytes
   */
  constructor(randomBytes: RandomBytes) {
    super({
      curve: createEd25519(randomBytes),
      randomBytes,
      curveName: 'Ed25519',
      signatureAlgorithmName: 'EdDSA',
      keyByteLength: 32,
    });
  }
}
