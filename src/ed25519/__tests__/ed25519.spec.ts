import { describe, it, expect } from 'vitest';
import { ed25519 as nobleEd25519 } from '@noble/curves/ed25519';
import { createEd25519 } from '../ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('ed25519 interoperability', () => {
  const ed25519 = createEd25519(randomBytes);

  it('should verify signatures between our implementation and noble/curves', () => {
    // Generate key pair using our implementation
    const ourPrivateKey = ed25519.utils.randomPrivateKey();
    const ourPublicKey = ed25519.getPublicKey(ourPrivateKey);

    // Generate key pair using noble/curves
    const noblePrivateKey = nobleEd25519.utils.randomPrivateKey();
    const noblePublicKey = nobleEd25519.getPublicKey(noblePrivateKey);

    // Create message using TextEncoder and convert to Uint8Array
    const ourMessage = new TextEncoder().encode('test message');
    const nobleMessage = Uint8Array.from(ourMessage);

    // Sign with our implementation, verify with noble/curves
    const ourSignature = ed25519.sign(ourMessage, ourPrivateKey);
    expect(nobleEd25519.verify(ourSignature, nobleMessage, ourPublicKey)).toBe(
      true,
    );

    // Sign with noble/curves, verify with our implementation
    const nobleSignature = nobleEd25519.sign(nobleMessage, noblePrivateKey);
    expect(ed25519.verify(nobleSignature, ourMessage, noblePublicKey)).toBe(
      true,
    );
  });

  it('should generate private keys with correct bit patterns after adjustScalarBytes', () => {
    const privateKey = ed25519.utils.randomPrivateKey();

    // Check length
    expect(privateKey.length).toBe(32);

    // Check first byte (lower 3 bits should be 0)
    expect(privateKey[0] & 0b00000111).toBe(0);

    // Check last byte (upper 2 bits should be 01)
    expect((privateKey[31] & 0b11000000) >>> 6).toBe(0b01);
  });
});
