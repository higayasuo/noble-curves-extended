import { describe, it, expect } from 'vitest';
import { secp256k1 as nobleSecp256k1 } from '@noble/curves/secp256k1';
import { createSecp256k1 } from '../secp256k1';
import { randomBytes as nodeRandomBytes } from 'crypto';
import { RandomBytes } from '../../types';

describe('secp256k1 interoperability', () => {
  const randomBytes: RandomBytes = (bytesLength?: number) => {
    return new Uint8Array(nodeRandomBytes(bytesLength ?? 32));
  };
  const ourSecp256k1 = createSecp256k1(randomBytes);

  it('should verify signature created by custom implementation using noble implementation', () => {
    // Generate key pair using custom implementation
    const privateKey = ourSecp256k1.utils.randomPrivateKey();
    const publicKey = ourSecp256k1.getPublicKey(privateKey);

    // Create message using TextEncoder
    const message = Uint8Array.from(
      new TextEncoder().encode('Hello, secp256k1!'),
    );
    const signature = ourSecp256k1.sign(message, privateKey);

    // Verify with noble implementation
    const isValid = nobleSecp256k1.verify(signature, message, publicKey);
    expect(isValid).toBe(true);
  });

  it('should verify signature created by noble implementation using custom implementation', () => {
    // Generate key pair using noble implementation
    const privateKey = nobleSecp256k1.utils.randomPrivateKey();
    const publicKey = nobleSecp256k1.getPublicKey(privateKey);

    // Create message using TextEncoder
    const message = Uint8Array.from(
      new TextEncoder().encode('Hello, secp256k1!'),
    );
    const signature = nobleSecp256k1.sign(message, privateKey);

    // Verify with custom implementation
    const isValid = ourSecp256k1.verify(signature, message, publicKey);
    expect(isValid).toBe(true);
  });

  it('should compute the same shared secret when using custom implementation with noble keys', () => {
    // Generate key pairs using noble implementation
    const alicePrivateKey = nobleSecp256k1.utils.randomPrivateKey();
    const alicePublicKey = nobleSecp256k1.getPublicKey(alicePrivateKey);

    const bobPrivateKey = nobleSecp256k1.utils.randomPrivateKey();
    const bobPublicKey = nobleSecp256k1.getPublicKey(bobPrivateKey);

    // Compute shared secrets using our implementation
    const aliceSharedSecret = ourSecp256k1.getSharedSecret(
      alicePrivateKey,
      bobPublicKey,
    );
    const bobSharedSecret = ourSecp256k1.getSharedSecret(
      bobPrivateKey,
      alicePublicKey,
    );

    // Verify that both parties compute the same shared secret
    expect(aliceSharedSecret).toEqual(bobSharedSecret);

    // Verify with noble implementation
    const nobleAliceSharedSecret = nobleSecp256k1.getSharedSecret(
      alicePrivateKey,
      bobPublicKey,
    );
    const nobleBobSharedSecret = nobleSecp256k1.getSharedSecret(
      bobPrivateKey,
      alicePublicKey,
    );

    // Verify that our implementation matches noble's
    expect(aliceSharedSecret).toEqual(nobleAliceSharedSecret);
    expect(bobSharedSecret).toEqual(nobleBobSharedSecret);
  });

  it('should compute the same shared secret when using noble implementation with custom keys', () => {
    // Generate key pairs using our implementation
    const alicePrivateKey = ourSecp256k1.utils.randomPrivateKey();
    const alicePublicKey = ourSecp256k1.getPublicKey(alicePrivateKey);

    const bobPrivateKey = ourSecp256k1.utils.randomPrivateKey();
    const bobPublicKey = ourSecp256k1.getPublicKey(bobPrivateKey);

    // Compute shared secrets using noble implementation
    const nobleAliceSharedSecret = nobleSecp256k1.getSharedSecret(
      alicePrivateKey,
      bobPublicKey,
    );
    const nobleBobSharedSecret = nobleSecp256k1.getSharedSecret(
      bobPrivateKey,
      alicePublicKey,
    );

    // Verify that both parties compute the same shared secret
    expect(nobleAliceSharedSecret).toEqual(nobleBobSharedSecret);

    // Verify with our implementation
    const aliceSharedSecret = ourSecp256k1.getSharedSecret(
      alicePrivateKey,
      bobPublicKey,
    );
    const bobSharedSecret = ourSecp256k1.getSharedSecret(
      bobPrivateKey,
      alicePublicKey,
    );

    // Verify that noble implementation matches ours
    expect(nobleAliceSharedSecret).toEqual(aliceSharedSecret);
    expect(nobleBobSharedSecret).toEqual(bobSharedSecret);
  });
});
