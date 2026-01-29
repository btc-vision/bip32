import type { TinySecp256k1Interface } from './bip32';
/**
 * Validates an ECC library for use with bip32.
 *
 * Delegates the bulk of verification to ecpair's {@link verifyCryptoBackend},
 * then checks the one additional primitive bip32 requires: `pointAddScalar`.
 */
export declare function testEcc(ecc: TinySecp256k1Interface): void;
