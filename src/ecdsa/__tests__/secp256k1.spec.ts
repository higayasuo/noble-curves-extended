import { describe, it, expect } from 'vitest';
import { secp256k1 as nobleSecp256k1 } from '@noble/curves/secp256k1';
import { createSecp256k1 } from '../secp256k1';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { RandomBytes } from '../../types';

describe('secp256k1 interoperability', () => {
  const randomBytes: RandomBytes = (bytesLength?: number) => {
    return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
  };
  const customSecp256k1 = createSecp256k1(randomBytes);

  it('should verify signature created by custom implementation using noble implementation', () => {
    // Generate key pair using custom implementation
    const privateKey = customSecp256k1.utils.randomPrivateKey();
    const publicKey = customSecp256k1.getPublicKey(privateKey);

    // Create message using TextEncoder
    const message = new TextEncoder().encode('Hello, secp256k1!');
    const nobleMessage = Uint8Array.from(message);
    const signature = customSecp256k1.sign(message, privateKey);

    // Verify with noble implementation
    const isValid = nobleSecp256k1.verify(signature, nobleMessage, publicKey);
    expect(isValid).toBe(true);
  });

  it('should verify signature created by noble implementation using custom implementation', () => {
    // Generate key pair using noble implementation
    const privateKey = nobleSecp256k1.utils.randomPrivateKey();
    const publicKey = nobleSecp256k1.getPublicKey(privateKey);

    // Create message using TextEncoder
    const message = new TextEncoder().encode('Hello, secp256k1!');
    const nobleMessage = Uint8Array.from(message);
    const signature = nobleSecp256k1.sign(nobleMessage, privateKey);

    // Verify with custom implementation
    const isValid = customSecp256k1.verify(signature, message, publicKey);
    expect(isValid).toBe(true);
  });
});
