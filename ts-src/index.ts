export {
  BIP32Factory as default,
  BIP32Factory,
  BIP32Interface,
  BIP32API,
  TinySecp256k1Interface,
} from './bip32.js';

// Quantum-resistant BIP32 using ML-DSA-87
export {
  QuantumBIP32Factory,
  QuantumBIP32Interface,
  QuantumBIP32API,
  QuantumSigner,
  MLDSA87KeyPair,
} from './quantum/index.js';
