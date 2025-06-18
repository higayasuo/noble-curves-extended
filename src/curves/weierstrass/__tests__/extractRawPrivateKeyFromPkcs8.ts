import * as asn1js from 'asn1js';

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
  return (block as asn1js.OctetString).valueBlock.valueHexView;
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
  // 1. Parse the DER byte array as ASN.1
  const pkcs8 = parseDER(pkcs8Array);

  // 2. Extract the PrivateKey (OCTET STRING)
  const privateKeyOctetString = extractOctetString(pkcs8.valueBlock.value[2]);
  const ecPrivateKeyAsn1 = parseDER(privateKeyOctetString);

  // 3. Retrieve the raw private key (OCTET STRING)
  return extractOctetString(ecPrivateKeyAsn1.valueBlock.value[1]);
};
