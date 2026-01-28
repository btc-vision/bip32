export {
  BIP32Factory as default,
  BIP32Factory,
  BIP32Interface,
  BIP32API,
  TinySecp256k1Interface,
} from './bip32.js';
export type { Signer as BIP32Signer } from './bip32.js';

// Network configurations
export { BITCOIN, TESTNET, REGTEST } from './networks.js';
export type { Network } from './types.js';

// Quantum-resistant BIP32 using ML-DSA
export {
  QuantumBIP32Factory,
  QuantumBIP32Interface,
  QuantumBIP32API,
  QuantumSigner,
  MLDSAKeyPair,
  MLDSASecurityLevel,
  MLDSAConfig,
  DEFAULT_SECURITY_LEVEL,
  getMLDSAConfig,
} from './quantum/index.js';

// Derivation path enums
export {
  DerivationPath,
  QuantumDerivationPath,
  getQuantumPath,
  getBitcoinPath,
} from './derivation-paths.js';
