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
    const message = Uint8Array.from(new TextEncoder().encode('test message'));

    // Sign with our implementation, verify with noble/curves
    const ourSignature = ed25519.sign(message, ourPrivateKey);
    expect(nobleEd25519.verify(ourSignature, message, ourPublicKey)).toBe(true);

    // Sign with noble/curves, verify with our implementation
    const nobleSignature = nobleEd25519.sign(message, noblePrivateKey);
    expect(ed25519.verify(nobleSignature, message, noblePublicKey)).toBe(true);
  });
});
