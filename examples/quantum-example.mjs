#!/usr/bin/env node

/**
 * Example demonstrating ML-DSA quantum-resistant BIP32 key derivation
 *
 * This example shows how to:
 * 1. Create quantum master keys with different security levels
 * 2. Derive child keys using standard derivation paths
 * 3. Sign and verify messages using ML-DSA
 * 4. Compare different security levels
 */

import {
  QuantumBIP32Factory,
  MLDSASecurityLevel,
  QuantumDerivationPath,
} from '../src/esm/quantum/index.js';
import { randomBytes } from 'crypto';

console.log('=== Quantum BIP32 Example with ML-DSA ===\n');

// 1. Create a seed (in production, use a BIP39 mnemonic)
const seed = randomBytes(32);
console.log('Seed:', seed.toString('hex').substring(0, 64) + '...\n');

// 2. Create master keys with different security levels
console.log('Creating master quantum keys with different security levels...');
console.log('\n--- ML-DSA-44 (Level 2 Security: 128-bit) ---');
const master44 = QuantumBIP32Factory.fromSeed(seed, MLDSASecurityLevel.LEVEL2);
console.log('✓ ML-DSA-44 key created (default)');
console.log('  Security Level:', master44.securityLevel);
console.log('  Public key size:', master44.publicKey.length, 'bytes');
console.log('  Private key size:', master44.privateKey.length, 'bytes');

console.log('\n--- ML-DSA-65 (Level 3 Security: 192-bit) ---');
const master65 = QuantumBIP32Factory.fromSeed(seed, MLDSASecurityLevel.LEVEL3);
console.log('✓ ML-DSA-65 key created');
console.log('  Security Level:', master65.securityLevel);
console.log('  Public key size:', master65.publicKey.length, 'bytes');
console.log('  Private key size:', master65.privateKey.length, 'bytes');

console.log('\n--- ML-DSA-87 (Level 5 Security: 256-bit) ---');
const master87 = QuantumBIP32Factory.fromSeed(seed, MLDSASecurityLevel.LEVEL5);
console.log('✓ ML-DSA-87 key created');
console.log('  Security Level:', master87.securityLevel);
console.log('  Public key size:', master87.publicKey.length, 'bytes');
console.log('  Private key size:', master87.privateKey.length, 'bytes\n');

// 3. Use the default (ML-DSA-44) for the rest of the example
const master = master44;

// 4. Derive child key using standard derivation path
console.log('Deriving child key using QuantumDerivationPath.STANDARD...');
const child = master.derivePath(QuantumDerivationPath.STANDARD);
console.log('✓ Child key derived at path:', QuantumDerivationPath.STANDARD);
console.log('  Depth:', child.depth);
console.log('  Index:', child.index);
console.log('  Public key size:', child.publicKey.length, 'bytes\n');

// 5. Sign a message
const message = new TextEncoder().encode('Hello, quantum-resistant Bitcoin!');
console.log('Signing message:', new TextDecoder().decode(message));
const signature = child.sign(message);
console.log('✓ Message signed with ML-DSA-44');
console.log('  Signature size:', signature.length, 'bytes\n');

// 6. Verify the signature
console.log('Verifying signature...');
const isValid = child.verify(message, signature);
console.log('✓ Signature verification:', isValid ? 'VALID' : 'INVALID\n');

// 7. Test with tampered message
const tamperedMessage = new TextEncoder().encode('Hello, quantum-resistant Bitcoin?');
console.log('Testing with tampered message...');
const isTamperedValid = child.verify(tamperedMessage, signature);
console.log('✓ Tampered signature verification:', isTamperedValid ? 'VALID' : 'INVALID (expected)\n');

// 8. Export and import keys
console.log('Testing key export/import...');
const exported = child.toBase58();
console.log('✓ Exported to base58 (length:', exported.length, 'chars)');
const imported = QuantumBIP32Factory.fromBase58(exported);
console.log('✓ Imported from base58');
console.log('  Security level preserved:', imported.securityLevel === child.securityLevel ? 'YES' : 'NO');

// Verify imported key works
const signature2 = imported.sign(message);
const isValid2 = child.verify(message, signature2);
console.log('✓ Imported key signature verification:', isValid2 ? 'VALID' : 'INVALID\n');

// 9. Create neutered (public-only) key
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

// 10. Compare signature sizes across security levels
console.log('=== Signature Size Comparison ===');
const child87 = master87.derivePath(QuantumDerivationPath.STANDARD);
const child65 = master65.derivePath(QuantumDerivationPath.STANDARD);

const sig44 = child.sign(message);
const sig65 = child65.sign(message);
const sig87 = child87.sign(message);

console.log('ML-DSA-44 signature:', sig44.length, 'bytes');
console.log('ML-DSA-65 signature:', sig65.length, 'bytes');
console.log('ML-DSA-87 signature:', sig87.length, 'bytes\n');
