import { hmac } from '@noble/hashes/hmac.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { Uint8ArrayOrBuffer } from './Buffer.js';

export function hash160(buffer: Uint8ArrayOrBuffer): Uint8ArrayOrBuffer {
  return ripemd160(sha256(buffer));
}

export function hash256(buffer: Uint8ArrayOrBuffer): Uint8ArrayOrBuffer {
  return sha256(buffer);
}

export function hmacSHA512(
  key: Uint8ArrayOrBuffer,
  data: Uint8ArrayOrBuffer,
): Uint8ArrayOrBuffer {
  return hmac(sha512, key, data);
}
