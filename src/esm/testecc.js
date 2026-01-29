import { verifyCryptoBackend } from '@btc-vision/ecpair';
import * as tools from 'uint8array-tools';
const h = (hex) => tools.fromHex(hex);
function assert(bool) {
    if (!bool)
        throw new Error('ecc library invalid');
}
/**
 * Validates an ECC library for use with bip32.
 *
 * Delegates the bulk of verification to ecpair's {@link verifyCryptoBackend},
 * then checks the one additional primitive bip32 requires: `pointAddScalar`.
 */
export function testEcc(ecc) {
    // Reuse ecpair's comprehensive known-answer tests.
    // At runtime TinySecp256k1Interface and CryptoBackend have identical shapes;
    // the cast is safe because the branded types erase to Uint8Array.
    verifyCryptoBackend(ecc);
    // bip32-specific: pointAddScalar is required for child key derivation.
    assert(tools.compare(ecc.pointAddScalar(h('0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'), h('0000000000000000000000000000000000000000000000000000000000000003')), h('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')) === 0);
}
