import { describe, it, expect } from 'vitest';
import { weierstrassRecoverPublicKey } from '../weierstrassRecoverPublicKey';
import { weierstrassSign } from '../weierstrassSign';
import { createP256 } from '@/curves/weierstrass/p256';
import { createP384 } from '@/curves/weierstrass/p384';
import { createP521 } from '@/curves/weierstrass/p521';
import { createSecp256k1 } from '@/curves/weierstrass/secp256k1';
import { randomBytes } from '@noble/hashes/utils';
import elliptic from 'elliptic';
import { fromRawSignature } from '@/curves/weierstrass/fromRawSignature';

const curves = [
  {
    name: 'P-256',
    createCurve: createP256,
    ellipticCurveName: 'p256',
  },
  {
    name: 'P-384',
    createCurve: createP384,
    ellipticCurveName: 'p384',
  },
  {
    name: 'P-521',
    createCurve: createP521,
    ellipticCurveName: 'p521',
  },
  {
    name: 'secp256k1',
    createCurve: createSecp256k1,
    ellipticCurveName: 'secp256k1',
  },
];

const message = new TextEncoder().encode('Hello, World!');

describe('weierstrassRecoverPublicKey', () => {
  describe('basic tests', () => {
    describe('compressed public key', () => {
      it.each(curves)(
        'should recover compressed public key for $name',
        ({ createCurve }) => {
          const curve = createCurve(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const expectedPublicKey = curve.getPublicKey(privateKey, true); // compressed

          // Create a recoverable signature using weierstrassSign
          const rawSignature = weierstrassSign(curve, {
            message,
            privateKey,
            recovered: true,
          });

          // Recover public key (compressed)
          const recoveredPublicKey = weierstrassRecoverPublicKey(curve, {
            signature: rawSignature,
            message,
            compressed: true,
          });

          expect(recoveredPublicKey).toEqual(expectedPublicKey);
        },
      );
    });

    describe('uncompressed public key', () => {
      it.each(curves)(
        'should recover uncompressed public key for $name',
        ({ createCurve }) => {
          const curve = createCurve(randomBytes);
          const privateKey = curve.utils.randomPrivateKey();
          const expectedPublicKey = curve.getPublicKey(privateKey, false); // uncompressed

          // Create a recoverable signature using weierstrassSign
          const rawSignature = weierstrassSign(curve, {
            message,
            privateKey,
            recovered: true,
          });

          // Recover public key (uncompressed)
          const recoveredPublicKey = weierstrassRecoverPublicKey(curve, {
            signature: rawSignature,
            message,
            compressed: false,
          });

          expect(recoveredPublicKey).toEqual(expectedPublicKey);
        },
      );
    });

    describe('compatibility tests', () => {
      describe('elliptic compatibility', () => {
        it.each(curves)(
          'should recover public key from elliptic signature for $name',
          ({ createCurve, ellipticCurveName }) => {
            const curve = createCurve(randomBytes);
            const ec = new elliptic.ec(ellipticCurveName);

            // Generate key pair using elliptic
            const ellipticKeyPair = ec.genKeyPair();
            const ellipticPrivateKey = Buffer.from(
              ellipticKeyPair
                .getPrivate()
                .toArray('be', curve.CURVE.nByteLength),
            );
            const ellipticPublicKey = new Uint8Array(
              ellipticKeyPair.getPublic().encode('array', false),
            );

            // Hash the message for compatibility with noble (prehash: true)
            const msgHash = curve.CURVE.hash(message);

            // Sign with elliptic (using hashed message)
            const ellipticSignature = ec.sign(
              Buffer.from(msgHash),
              ellipticPrivateKey,
              { canonical: true },
            );

            // Create recoverable signature format
            const signature = new Uint8Array([
              ...ellipticSignature.r.toArray('be', curve.CURVE.nByteLength),
              ...ellipticSignature.s.toArray('be', curve.CURVE.nByteLength),
              ellipticSignature.recoveryParam!, // Add recovery parameter
            ]);

            // Recover public key using our implementation
            const recoveredPublicKey = weierstrassRecoverPublicKey(curve, {
              signature,
              message,
              compressed: false,
            });

            expect(recoveredPublicKey).toEqual(ellipticPublicKey);
          },
        );

        it.each(curves)(
          'should recover public key from our signature using elliptic for $name',
          ({ createCurve, ellipticCurveName }) => {
            const curve = createCurve(randomBytes);
            const ec = new elliptic.ec(ellipticCurveName);

            // Generate key pair using our implementation
            const privateKey = curve.utils.randomPrivateKey();
            const expectedPublicKey = curve.getPublicKey(privateKey, false); // uncompressed

            // Create a recoverable signature using weierstrassSign
            const rawSignature = weierstrassSign(curve, {
              message,
              privateKey,
              recovered: true,
            });

            // Recover public key using our implementation
            const recoveredPublicKey = weierstrassRecoverPublicKey(curve, {
              signature: rawSignature,
              message,
              compressed: false,
            });

            expect(recoveredPublicKey).toEqual(expectedPublicKey);

            // Verify that elliptic can also recover the same public key
            const msgHash = curve.CURVE.hash(message);
            const signature = fromRawSignature(curve, rawSignature);
            const ellipticRecovered = ec.recoverPubKey(
              Buffer.from(msgHash),
              {
                r: signature.r.toString(16),
                s: signature.s.toString(16),
              },
              signature.recovery!,
            );

            const ellipticRecoveredBytes = new Uint8Array(
              ellipticRecovered.encode('array', false),
            );

            expect(ellipticRecoveredBytes).toEqual(expectedPublicKey);
          },
        );
      });

      describe('error handling tests', () => {
        it.each(curves)(
          'should throw error for invalid signature for $name',
          ({ createCurve }) => {
            const curve = createCurve(randomBytes);
            const invalidSignature = new Uint8Array(64); // Wrong length

            expect(() =>
              weierstrassRecoverPublicKey(curve, {
                signature: invalidSignature,
                message,
              }),
            ).toThrow('Failed to recover public key');
          },
        );

        it.each(curves)(
          'should throw error for empty signature for $name',
          ({ createCurve }) => {
            const curve = createCurve(randomBytes);
            const emptySignature = new Uint8Array(0);

            expect(() =>
              weierstrassRecoverPublicKey(curve, {
                signature: emptySignature,
                message,
              }),
            ).toThrow('Failed to recover public key');
          },
        );

        it.each(curves)(
          'should throw error for non-recoverable signature for $name',
          ({ createCurve }) => {
            const curve = createCurve(randomBytes);
            const privateKey = curve.utils.randomPrivateKey();

            // Create a non-recoverable signature using weierstrassSign
            const compactSignature = weierstrassSign(curve, {
              message,
              privateKey,
              recovered: false,
            });

            expect(() =>
              weierstrassRecoverPublicKey(curve, {
                signature: compactSignature,
                message,
              }),
            ).toThrow('Failed to recover public key');
          },
        );
      });
    });
  });
});
