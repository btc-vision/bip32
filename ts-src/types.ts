const BIP32_PATH_REGEX = /^(m\/)?(\d+'?\/)*\d+'?$/;

export function validateBip32Path(path: string): void {
  if (typeof path !== 'string' || !BIP32_PATH_REGEX.test(path)) {
    throw new TypeError('Expected BIP32 derivation path');
  }
}

export function validateBytes32(buf: Uint8Array): void {
  if (!(buf instanceof Uint8Array) || buf.length !== 32) {
    throw new TypeError('Expected Uint8Array of length 32');
  }
}

export function validateBytes33(buf: Uint8Array): void {
  if (!(buf instanceof Uint8Array) || buf.length !== 33) {
    throw new TypeError('Expected Uint8Array of length 33');
  }
}
