import { describe, it, expect } from 'vitest';
import { ec as EC } from 'elliptic';
import { createSecp256k1 } from '../secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 as nobleSecp256k1 } from '@noble/curves/secp256k1';

const ec = new EC('secp256k1');

const toHex = (u8: Uint8Array) => Buffer.from(u8).toString('hex');
const fromHex = (hex: string) => new Uint8Array(Buffer.from(hex, 'hex'));

describe('secp256k1 interoperability', () => {
  const ourSecp256k1 = createSecp256k1(randomBytes);

  describe('sign and verify', () => {
    describe('noble compatibility', () => {
      it('should verify signature created by our implementation using noble implementation', () => {
        // Generate key pair using our implementation
        const privateKey = ourSecp256k1.utils.randomPrivateKey();
        const publicKey = ourSecp256k1.getPublicKey(privateKey, false);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, secp256k1!'),
        );
        const signature = ourSecp256k1.sign(message, privateKey, {
          prehash: true,
        });
        // Verify with noble implementation
        const isValid = nobleSecp256k1.verify(signature, message, publicKey, {
          prehash: true,
        });
        expect(isValid).toBe(true);
      });

      it('should verify signature created by noble implementation using our implementation', () => {
        // Generate key pair using noble implementation
        const privateKey = nobleSecp256k1.utils.randomPrivateKey();
        const publicKey = nobleSecp256k1.getPublicKey(privateKey, false);
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, secp256k1!'),
        );
        const signature = nobleSecp256k1.sign(message, privateKey, {
          prehash: true,
        });
        // Verify with our implementation
        const isValid = ourSecp256k1.verify(signature, message, publicKey, {
          prehash: true,
        });
        expect(isValid).toBe(true);
      });
    });

    describe('elliptic compatibility', () => {
      it('should verify signature created by our implementation using elliptic', () => {
        // Generate key pair using our implementation
        const privateKey = ourSecp256k1.utils.randomPrivateKey();
        const publicKey = ourSecp256k1.getPublicKey(privateKey, false); // uncompressed
        // Create message
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, secp256k1!'),
        );
        const signature = ourSecp256k1.sign(message, privateKey, {
          prehash: true,
        });
        const derSig = signature.toDERHex();
        // Verify with elliptic
        const key = ec.keyFromPublic(publicKey);
        const isValid = key.verify(sha256(message), derSig);
        expect(isValid).toBe(true);
      });

      it('should verify signature created by elliptic using our implementation', () => {
        // Generate key pair using elliptic
        const key = ec.genKeyPair();
        const publicKeyHex = key.getPublic(true, 'hex');
        const publicKey = fromHex(publicKeyHex);
        // Create message
        const message = Uint8Array.from(
          new TextEncoder().encode('Hello, secp256k1!'),
        );
        const signature = key.sign(sha256(message));
        const derSig = signature.toDER('hex');
        // Verify with our implementation
        const isValid = ourSecp256k1.verify(
          fromHex(derSig),
          message,
          publicKey,
          { prehash: true },
        );
        expect(isValid).toBe(true);
      });
    });
  });

  describe('getSharedSecret', () => {
    describe('noble compatibility', () => {
      it('should compute the same shared secret when using our implementation with noble keys', () => {
        // Generate key pairs using noble implementation
        const alicePrivateKey = nobleSecp256k1.utils.randomPrivateKey();
        const alicePublicKey = nobleSecp256k1.getPublicKey(
          alicePrivateKey,
          false,
        );
        const bobPrivateKey = nobleSecp256k1.utils.randomPrivateKey();
        const bobPublicKey = nobleSecp256k1.getPublicKey(bobPrivateKey, false);
        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourSecp256k1.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourSecp256k1.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);
        // Compute shared secrets using noble implementation
        const nobleAliceSharedSecret = nobleSecp256k1.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const nobleBobSharedSecret = nobleSecp256k1.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(nobleAliceSharedSecret);
        expect(bobSharedSecret).toEqual(nobleBobSharedSecret);
      });

      it('should compute the same shared secret when using noble implementation with our keys', () => {
        // Generate key pairs using our implementation
        const alicePrivateKey = ourSecp256k1.utils.randomPrivateKey();
        const alicePublicKey = ourSecp256k1.getPublicKey(
          alicePrivateKey,
          false,
        );
        const bobPrivateKey = ourSecp256k1.utils.randomPrivateKey();
        const bobPublicKey = ourSecp256k1.getPublicKey(bobPrivateKey, false);
        // Compute shared secrets using noble implementation
        const nobleAliceSharedSecret = nobleSecp256k1.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const nobleBobSharedSecret = nobleSecp256k1.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(nobleAliceSharedSecret).toEqual(nobleBobSharedSecret);
        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourSecp256k1.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourSecp256k1.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(nobleAliceSharedSecret).toEqual(aliceSharedSecret);
        expect(nobleBobSharedSecret).toEqual(bobSharedSecret);
      });
    });

    describe('elliptic compatibility', () => {
      it('should compute the same shared secret using our implementation and elliptic', () => {
        // Generate key pairs using elliptic
        const alice = ec.genKeyPair();
        const bob = ec.genKeyPair();
        const alicePrivateKey = fromHex(alice.getPrivate('hex'));
        const alicePublicKey = fromHex(alice.getPublic(true, 'hex'));
        const bobPrivateKey = fromHex(bob.getPrivate('hex'));
        const bobPublicKey = fromHex(bob.getPublic(true, 'hex'));
        // Compute shared secrets using our implementation
        const aliceSharedSecret = ourSecp256k1.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourSecp256k1.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);
        // Compute shared secrets using elliptic
        const ellipticAliceShared = fromHex(
          alice.derive(bob.getPublic()).toString('hex').padStart(64, '0'),
        );
        const ellipticBobShared = fromHex(
          bob.derive(alice.getPublic()).toString('hex').padStart(64, '0'),
        );
        expect(ellipticAliceShared).toEqual(ellipticBobShared);
        // Compare with our implementation (last 32 bytes)
        expect(aliceSharedSecret.slice(1)).toEqual(ellipticAliceShared);
        expect(bobSharedSecret.slice(1)).toEqual(ellipticBobShared);
      });

      it('should compute the same shared secret using elliptic with ourSecp256k1 keys', () => {
        // Generate key pairs using ourSecp256k1
        const alicePrivateKey = ourSecp256k1.utils.randomPrivateKey();
        const alicePublicKey = ourSecp256k1.getPublicKey(
          alicePrivateKey,
          false,
        );
        const bobPrivateKey = ourSecp256k1.utils.randomPrivateKey();
        const bobPublicKey = ourSecp256k1.getPublicKey(bobPrivateKey, false);

        // Import keys into elliptic
        const aliceKey = ec.keyFromPrivate(toHex(alicePrivateKey), 'hex');
        const bobKey = ec.keyFromPrivate(toHex(bobPrivateKey), 'hex');
        const alicePub = aliceKey.getPublic();
        const bobPub = bobKey.getPublic();

        // Compute shared secrets using ourSecp256k1
        const aliceSharedSecret = ourSecp256k1.getSharedSecret(
          alicePrivateKey,
          bobPublicKey,
        );
        const bobSharedSecret = ourSecp256k1.getSharedSecret(
          bobPrivateKey,
          alicePublicKey,
        );
        expect(aliceSharedSecret).toEqual(bobSharedSecret);

        // Compute shared secrets using elliptic
        const ellipticAliceShared = fromHex(
          aliceKey.derive(bobPub).toString('hex').padStart(64, '0'),
        );
        const ellipticBobShared = fromHex(
          bobKey.derive(alicePub).toString('hex').padStart(64, '0'),
        );
        expect(ellipticAliceShared).toEqual(ellipticBobShared);
        // Compare with our implementation (last 32 bytes or slice(1))
        expect(aliceSharedSecret.slice(1)).toEqual(ellipticAliceShared);
        expect(bobSharedSecret.slice(1)).toEqual(ellipticBobShared);
      });
    });
  });
});
