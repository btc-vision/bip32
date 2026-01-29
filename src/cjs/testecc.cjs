"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.testEcc = testEcc;
const ecpair_1 = require("@btc-vision/ecpair");
const tools = __importStar(require("uint8array-tools"));
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
function testEcc(ecc) {
    // Reuse ecpair's comprehensive known-answer tests.
    // At runtime TinySecp256k1Interface and CryptoBackend have identical shapes;
    // the cast is safe because the branded types erase to Uint8Array.
    (0, ecpair_1.verifyCryptoBackend)(ecc);
    // bip32-specific: pointAddScalar is required for child key derivation.
    assert(tools.compare(ecc.pointAddScalar(h('0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'), h('0000000000000000000000000000000000000000000000000000000000000003')), h('02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')) === 0);
}
