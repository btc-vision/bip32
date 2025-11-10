import { Uint8ArrayOrBuffer } from '../Buffer.js';

/**
 * ML-DSA-87 key pair interface
 * ML-DSA-87 provides Level 5 security (256-bit classical security)
 */
export interface MLDSA87KeyPair {
  /** 4896-byte private key containing polynomial vectors and matrices */
  privateKey: Uint8ArrayOrBuffer;
  /** 2592-byte public key */
  publicKey: Uint8ArrayOrBuffer;
}

/**
 * Quantum-resistant signer interface using ML-DSA-87
 */
export interface QuantumSigner {
  publicKey: Uint8ArrayOrBuffer;
  privateKey?: Uint8ArrayOrBuffer;

  /**
   * Sign a message hash using ML-DSA-87
   * @param hash - The hash to sign
   * @returns ML-DSA-87 signature
   */
  sign(hash: Uint8ArrayOrBuffer): Uint8ArrayOrBuffer;

  /**
   * Verify a signature using ML-DSA-87
   * @param hash - The hash that was signed
   * @param signature - The ML-DSA-87 signature to verify
   * @returns true if signature is valid
   */
  verify(hash: Uint8ArrayOrBuffer, signature: Uint8ArrayOrBuffer): boolean;
}

/**
 * Quantum BIP32 interface extending standard BIP32 with ML-DSA-87 support
 */
export interface QuantumBIP32Interface extends QuantumSigner {
  chainCode: Uint8ArrayOrBuffer;
  depth: number;
  index: number;
  parentFingerprint: number;
  identifier: Uint8ArrayOrBuffer;
  fingerprint: Uint8ArrayOrBuffer;

  /**
   * Check if this is a neutered (public-only) key
   */
  isNeutered(): boolean;

  /**
   * Create a neutered (public-only) version of this key
   */
  neutered(): QuantumBIP32Interface;

  /**
   * Derive a child key at the given index
   * @param index - Child index (use >= 0x80000000 for hardened)
   */
  derive(index: number): QuantumBIP32Interface;

  /**
   * Derive a hardened child key
   * @param index - Child index (will be made hardened automatically)
   */
  deriveHardened(index: number): QuantumBIP32Interface;

  /**
   * Derive a key using a BIP32 path (e.g., "m/360'/0'/0'/0/0")
   * @param path - BIP32 derivation path
   */
  derivePath(path: string): QuantumBIP32Interface;

  /**
   * Export as base58-encoded extended key
   */
  toBase58(): string;
}

/**
 * Quantum BIP32 API interface
 */
export interface QuantumBIP32API {
  /**
   * Create a quantum master key from a seed
   * Uses ML-DSA-87 for key generation
   * @param seed - Seed bytes (16-64 bytes)
   */
  fromSeed(seed: Uint8ArrayOrBuffer): QuantumBIP32Interface;

  /**
   * Import a quantum key from base58
   * @param inString - Base58-encoded extended key
   */
  fromBase58(inString: string): QuantumBIP32Interface;

  /**
   * Create quantum key from public key and chain code
   * @param publicKey - ML-DSA-87 public key (2592 bytes)
   * @param chainCode - Chain code (32 bytes)
   */
  fromPublicKey(
    publicKey: Uint8ArrayOrBuffer,
    chainCode: Uint8ArrayOrBuffer,
  ): QuantumBIP32Interface;

  /**
   * Create quantum key from private key and chain code
   * @param privateKey - ML-DSA-87 private key (4896 bytes)
   * @param chainCode - Chain code (32 bytes)
   */
  fromPrivateKey(
    privateKey: Uint8ArrayOrBuffer,
    chainCode: Uint8ArrayOrBuffer,
  ): QuantumBIP32Interface;
}
