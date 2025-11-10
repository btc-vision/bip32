#!/usr/bin/env node

/**
 * Example demonstrating ML-DSA-87 quantum-resistant BIP32 key derivation
 *
 * This example shows how to:
 * 1. Create a quantum master key from a seed
 * 2. Derive child keys using BIP32 paths
 * 3. Sign and verify messages using ML-DSA-87
 */

import { QuantumBIP32Factory } from '../src/esm/quantum/index.js';
import { randomBytes } from 'crypto';

console.log('=== Quantum BIP32 Example with ML-DSA-87 ===\n');

// 1. Create a seed (in production, use a BIP39 mnemonic)
const seed = randomBytes(32);
console.log('Seed:', seed.toString('hex').substring(0, 64) + '...\n');

// 2. Create master key from seed
console.log('Creating master quantum key...');
const master = QuantumBIP32Factory.fromSeed(seed);
console.log('✓ Master key created');
console.log('  Public key size:', master.publicKey.length, 'bytes');
console.log('  Private key size:', master.privateKey.length, 'bytes\n');

// 3. Derive child key at path m/360'/0'/0'/0/0
console.log('Deriving child key at path m/360\'/0\'/0\'/0/0...');
const child = master.derivePath("m/360'/0'/0'/0/0");
console.log('✓ Child key derived');
console.log('  Depth:', child.depth);
console.log('  Index:', child.index);
console.log('  Public key size:', child.publicKey.length, 'bytes\n');

// 4. Sign a message
const message = new TextEncoder().encode('Hello, quantum-resistant Bitcoin!');
console.log('Signing message:', new TextDecoder().decode(message));
const signature = child.sign(message);
console.log('✓ Message signed');
console.log('  Signature size:', signature.length, 'bytes\n');

// 5. Verify the signature
console.log('Verifying signature...');
const isValid = child.verify(message, signature);
console.log('✓ Signature verification:', isValid ? 'VALID' : 'INVALID\n');

// 6. Test with tampered message
const tamperedMessage = new TextEncoder().encode('Hello, quantum-resistant Bitcoin?');
console.log('Testing with tampered message...');
const isTamperedValid = child.verify(tamperedMessage, signature);
console.log('✓ Tampered signature verification:', isTamperedValid ? 'VALID' : 'INVALID (expected)\n');

// 7. Export and import keys
console.log('Testing key export/import...');
const exported = child.toBase58();
console.log('✓ Exported to base58 (length:', exported.length, 'chars)');
const imported = QuantumBIP32Factory.fromBase58(exported);
console.log('✓ Imported from base58');

// Verify imported key works
const signature2 = imported.sign(message);
const isValid2 = child.verify(message, signature2);
console.log('✓ Imported key signature verification:', isValid2 ? 'VALID' : 'INVALID\n');

// 8. Create neutered (public-only) key
console.log('Creating neutered (public-only) key...');
const publicOnly = child.neutered();
console.log('✓ Neutered key created');
console.log('  Is neutered:', publicOnly.isNeutered());
console.log('  Can verify:', publicOnly.verify(message, signature) ? 'YES' : 'NO');

try {
  publicOnly.sign(message);
  console.log('  Can sign: YES (unexpected!)');
} catch (e) {
  console.log('  Can sign: NO (expected)\n');
}
