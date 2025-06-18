import * as asn1js from 'asn1js';

// OID definition (DER format)
const OID_X25519_STRING = '1.3.101.110';
const OID_ED25519_STRING = '1.3.101.112';

/**
 * Parses a DER encoded ArrayBuffer into an ASN.1 Sequence.
 *
 * @param derArray - The DER encoded data.
 * @returns The parsed ASN.1 sequence.
 */
export const parseDER = (derArray: ArrayBuffer): asn1js.Sequence => {
  const asn1 = asn1js.fromBER(derArray);
  return asn1.result as asn1js.Sequence;
};

/**
 * Extracts the value of an OCTET STRING from an ASN.1 block.
 *
 * @param block - The ASN.1 block containing the OCTET STRING.
 * @returns The extracted OCTET STRING value.
 */
export const extractOctetString = (block: asn1js.BaseBlock): ArrayBuffer => {
  if (block instanceof asn1js.OctetString) {
    return block.valueBlock.valueHexView;
  }

  throw new Error('Invalid ASN.1 structure for OCTET STRING');
};

/**
 * Checks if the given OID string corresponds to an OKP (Octet Key Pair).
 *
 * @param oidString - The OID string to check.
 * @returns True if the OID string is for an OKP, false otherwise.
 */
export const isOkp = (oidString: string): boolean => {
  return oidString === OID_X25519_STRING || oidString === OID_ED25519_STRING;
};

/**
 * Extracts the algorithm OID string from an ASN.1 block.
 *
 * @param block - The ASN.1 block containing the algorithm identifier.
 * @returns The algorithm OID string.
 */
export const extractAlgorithmOidString = (block: asn1js.BaseBlock): string => {
  const algorithmIdentifier = block as asn1js.Sequence;
  const algorithmOidElement = algorithmIdentifier.valueBlock
    .value[0] as asn1js.ObjectIdentifier;

  return algorithmOidElement.valueBlock.toString();
};

/**
 * Extracts the private key from an OKP ASN.1 block.
 *
 * @param block - The ASN.1 block containing the OKP private key.
 * @returns The extracted private key as an ArrayBuffer.
 */
export const extractOkpPrivateKey = (block: asn1js.BaseBlock): ArrayBuffer => {
  const privateKeyOctetString = extractOctetString(block);
  const privateKeyAsn1 = asn1js.fromBER(privateKeyOctetString).result;
  return extractOctetString(privateKeyAsn1);
};

/**
 * Extracts the private key from an EC ASN.1 block.
 *
 * @param block - The ASN.1 block containing the EC private key.
 * @returns The extracted private key as an ArrayBuffer.
 * @throws Will throw an error if the ASN.1 structure is invalid for an EC private key.
 */
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
 * @param pkcs8Array - The PKCS#8 encoded private key.
 * @returns The raw private key as an ArrayBuffer.
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
