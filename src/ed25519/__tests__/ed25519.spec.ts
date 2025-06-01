import { describe, it, expect } from 'vitest';
import { ed25519 as nobleEd25519 } from '@noble/curves/ed25519';
import { createEd25519 } from '../ed25519';
import { randomBytes } from '@noble/hashes/utils';

describe('ed25519 interoperability', () => {
  const ourEd25519 = createEd25519(randomBytes);

  it('should verify signatures between our implementation and noble/curves', () => {
    // Generate key pair using our implementation
    const ourPrivateKey = ourEd25519.utils.randomPrivateKey();
    const ourPublicKey = ourEd25519.getPublicKey(ourPrivateKey);

    // Generate key pair using noble/curves
    const noblePrivateKey = nobleEd25519.utils.randomPrivateKey();
    const noblePublicKey = nobleEd25519.getPublicKey(noblePrivateKey);

    // Create message using TextEncoder and convert to Uint8Array
    const ourMessage = new TextEncoder().encode('test message');
    const nobleMessage = Uint8Array.from(ourMessage);

    // Sign with our implementation, verify with noble/curves
    const ourSignature = ourEd25519.sign(ourMessage, ourPrivateKey);
    expect(nobleEd25519.verify(ourSignature, nobleMessage, ourPublicKey)).toBe(
      true,
    );

    // Sign with noble/curves, verify with our implementation
    const nobleSignature = nobleEd25519.sign(nobleMessage, noblePrivateKey);
    expect(ourEd25519.verify(nobleSignature, ourMessage, noblePublicKey)).toBe(
      true,
    );
  });
});
