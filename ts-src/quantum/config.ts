import {
  ml_dsa44,
  ml_dsa65,
  ml_dsa87,
} from '@btc-vision/post-quantum/ml-dsa.js';
import { Network } from '../types.js';
import { BITCOIN, TESTNET, REGTEST } from '../networks.js';

/**
 * ML-DSA security levels
 *
 * These correspond to NIST security levels:
 * - LEVEL2: 128-bit classical security (ML-DSA-44)
 * - LEVEL3: 192-bit classical security (ML-DSA-65)
 * - LEVEL5: 256-bit classical security (ML-DSA-87)
 */
export enum MLDSASecurityLevel {
  /** Level 2 security - 128-bit classical security (smallest keys) */
  LEVEL2 = 44,

  /** Level 3 security - 192-bit classical security (balanced) */
  LEVEL3 = 65,

  /** Level 5 security - 256-bit classical security (highest security) */
  LEVEL5 = 87,
}

/**
 * ML-DSA algorithm configuration
 */
export interface MLDSAConfig {
  /** Security level identifier */
  level: MLDSASecurityLevel;
  /** Private key size in bytes */
  privateKeySize: number;
  /** Public key size in bytes */
  publicKeySize: number;
  /** Signature size in bytes */
  signatureSize: number;
  /** The actual ML-DSA implementation from post-quantum library */
  algorithm: typeof ml_dsa44 | typeof ml_dsa65 | typeof ml_dsa87;
  /** Network configuration */
  network: Network;
}

/**
 * Base configurations for each security level (network-agnostic)
 */
const BASE_CONFIGS: Record<MLDSASecurityLevel, Omit<MLDSAConfig, 'network'>> = {
  [MLDSASecurityLevel.LEVEL2]: {
    level: MLDSASecurityLevel.LEVEL2,
    privateKeySize: 2560,
    publicKeySize: 1312,
    signatureSize: 2420,
    algorithm: ml_dsa44,
  },
  [MLDSASecurityLevel.LEVEL3]: {
    level: MLDSASecurityLevel.LEVEL3,
    privateKeySize: 4032,
    publicKeySize: 1952,
    signatureSize: 3309,
    algorithm: ml_dsa65,
  },
  [MLDSASecurityLevel.LEVEL5]: {
    level: MLDSASecurityLevel.LEVEL5,
    privateKeySize: 4896,
    publicKeySize: 2592,
    signatureSize: 4627,
    algorithm: ml_dsa87,
  },
};

/**
 * Default security level (Level 2 - 128-bit classical security)
 */
export const DEFAULT_SECURITY_LEVEL: MLDSASecurityLevel =
  MLDSASecurityLevel.LEVEL2;

/**
 * Get ML-DSA configuration for a specific security level and network
 * @param level - Security level (44, 65, or 87)
 * @param network - Network configuration
 */
export function getMLDSAConfig(
  level: MLDSASecurityLevel,
  network: Network,
): MLDSAConfig {
  const baseConfig = BASE_CONFIGS[level];
  if (!baseConfig) {
    throw new TypeError(
      `Invalid ML-DSA security level: ${level}. Must be MLDSASecurityLevel.LEVEL2 (44), LEVEL3 (65), or LEVEL5 (87)`,
    );
  }

  return {
    ...baseConfig,
    network,
  };
}

/**
 * Find matching network and determine if private/public by version bytes
 * Used when importing from base58
 */
export function findNetworkByVersion(
  version: number,
): { network: Network; isPrivate: boolean } | null {
  // Try common networks first
  const commonNetworks = [BITCOIN, TESTNET, REGTEST];

  for (const network of commonNetworks) {
    if (version === network.bip32.private) {
      return { network, isPrivate: true };
    }
    if (version === network.bip32.public) {
      return { network, isPrivate: false };
    }
  }

  // For unknown networks, we can't determine which network it is
  // The caller will need to have the network object or fail
  return null;
}
