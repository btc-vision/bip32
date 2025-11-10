import { hmac } from '@noble/hashes/hmac';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
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
