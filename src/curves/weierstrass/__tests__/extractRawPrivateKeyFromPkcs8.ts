import * as asn1js from 'asn1js';

// OID definition (DER format)
const OID_X25519_STRING = '1.3.101.110';
const OID_ED25519_STRING = '1.3.101.112';

/**
 * Parses a DER encoded ArrayBuffer into an ASN.1 Sequence.
 *
 * @param {ArrayBuffer} derArray - The DER encoded data.
 * @returns {asn1js.Sequence} The parsed ASN.1 sequence.
 */
export const parseDER = (derArray: ArrayBuffer): asn1js.Sequence => {
  const asn1 = asn1js.fromBER(derArray);
  return asn1.result as asn1js.Sequence;
};

/**
 * Extracts the value of an OCTET STRING from an ASN.1 block.
 *
 * @param {asn1js.BaseBlock} block - The ASN.1 block containing the OCTET STRING.
 * @returns {ArrayBuffer} The extracted OCTET STRING value.
 */
export const extractOctetString = (block: asn1js.BaseBlock): ArrayBuffer => {
  if (block instanceof asn1js.OctetString) {
    return block.valueBlock.valueHexView;
  }

  throw new Error('Invalid ASN.1 structure for OCTET STRING');
};

export const isOkp = (oidString: string): boolean => {
  return oidString === OID_X25519_STRING || oidString === OID_ED25519_STRING;
};

export const extractAlgorithmOidString = (block: asn1js.BaseBlock): string => {
  const algorithmIdentifier = block as asn1js.Sequence;
  const algorithmOidElement = algorithmIdentifier.valueBlock
    .value[0] as asn1js.ObjectIdentifier;

  return algorithmOidElement.valueBlock.toString();
};

export const extractOkpPrivateKey = (block: asn1js.BaseBlock): ArrayBuffer => {
  const privateKeyOctetString = extractOctetString(block);
  const privateKeyAsn1 = asn1js.fromBER(privateKeyOctetString).result;
  return extractOctetString(privateKeyAsn1);
};

export const extractEcPrivateKey = (block: asn1js.BaseBlock): ArrayBuffer => {
  const privateKeyOctetString = extractOctetString(block);
  const ecPrivateKeyAsn1 = parseDER(privateKeyOctetString);
  if (ecPrivateKeyAsn1.valueBlock.value[1]) {
    return extractOctetString(ecPrivateKeyAsn1.valueBlock.value[1]);
  }
  throw new Error('Invalid ASN.1 structure for EC private key');
};

/**
 * Extracts the raw private key from a PKCS#8 encoded ArrayBuffer.
 *
 * @param {ArrayBuffer} pkcs8Array - The PKCS#8 encoded private key.
 * @returns {ArrayBuffer} The raw private key as an ArrayBuffer.
 */
export const extractRawPrivateKeyFromPkcs8 = (
  pkcs8Array: ArrayBuffer,
): ArrayBuffer => {
  // Parse the DER byte array as ASN.1
  const pkcs8 = parseDER(pkcs8Array);

  // Retrieve AlgorithmIdentifier
  const algorithmOidString = extractAlgorithmOidString(
    pkcs8.valueBlock.value[1],
  );
  // Check for OKP (OID string comparison)
  if (isOkp(algorithmOidString)) {
    return extractOkpPrivateKey(pkcs8.valueBlock.value[2]);
  }

  // Traditional EC key processing
  return extractEcPrivateKey(pkcs8.valueBlock.value[2]);
};
