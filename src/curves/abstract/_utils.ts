const _0n = /* @__PURE__ */ BigInt(0);

// Is positive bigint
const isPosBig = (n: bigint) => typeof n === 'bigint' && _0n <= n;

export function inRange(n: bigint, min: bigint, max: bigint): boolean {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}

/**
 * Asserts min <= n < max. NOTE: It's < max and not <= max.
 * @example
 * aInRange('x', x, 1n, 256n); // would assume x is in (1n..255n)
 */
export function aInRange(
  title: string,
  n: bigint,
  min: bigint,
  max: bigint,
): void {
  // Why min <= n < max and not a (min < n < max) OR b (min <= n <= max)?
  // consider P=256n, min=0n, max=P
  // - a for min=0 would require -1:          `inRange('x', x, -1n, P)`
  // - b would commonly require subtraction:  `inRange('x', x, 0n, P - 1n)`
  // - our way is the cleanest:               `inRange('x', x, 0n, P)
  if (!inRange(n, min, max))
    throw new Error(
      'expected valid ' + title + ': ' + min + ' <= n < ' + max + ', got ' + n,
    );
}

export function _validateObject(
  object: Record<string, any>,
  fields: Record<string, string>,
  optFields: Record<string, string> = {},
): void {
  if (!object || typeof object !== 'object')
    throw new Error('expected valid options object');
  type Item = keyof typeof object;
  function checkField(fieldName: Item, expectedType: string, isOpt: boolean) {
    const val = object[fieldName];
    if (isOpt && val === undefined) return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new Error(
        `param "${fieldName}" is invalid: expected ${expectedType}, got ${current}`,
      );
  }
  Object.entries(fields).forEach(([k, v]) => checkField(k, v, false));
  Object.entries(optFields).forEach(([k, v]) => checkField(k, v, true));
}
