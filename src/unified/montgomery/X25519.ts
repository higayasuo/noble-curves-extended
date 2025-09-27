import { RandomBytes } from '@/curves/types';
import { Montgomery } from './Montgomery';
import { createX25519 } from '@/curves/montgomery/x25519';

/**
 * X25519 elliptic curve implementation for ECDH key exchange.
 *
 * This class provides a unified interface for X25519 curve operations,
 * extending the base Montgomery curve implementation with X25519-specific
 * parameters and configuration.
 */
export class X25519 extends Montgomery {
  /**
   * Creates a new X25519 curve instance.
   *
   * @param {RandomBytes} randomBytes - A function to generate cryptographically secure random bytes.
   */
  constructor(randomBytes: RandomBytes) {
    super({
      curve: createX25519(randomBytes),
      randomBytes,
      curveName: 'X25519',
      keyByteLength: 32,
    });
  }
}
