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
exports.QuantumBIP32Factory = void 0;
const ml_dsa_js_1 = require("@btc-vision/post-quantum/ml-dsa.js");
const utils_js_1 = require("@btc-vision/post-quantum/utils.js");
const crypto = __importStar(require("../crypto.cjs"));
const tools = __importStar(require("uint8array-tools"));
const v = __importStar(require("valibot"));
const types_js_1 = require("../types.cjs");
const base_1 = require("@scure/base");
const sha256_1 = require("@noble/hashes/sha256");
const _bs58check = (0, base_1.base58check)(sha256_1.sha256);
const bs58check = {
    encode: (data) => _bs58check.encode(data),
    decode: (str) => _bs58check.decode(str),
};
// Constants for ML-DSA-87
const MLDSA87_PRIVATE_KEY_SIZE = 4896;
const MLDSA87_PUBLIC_KEY_SIZE = 2592;
const CHAIN_CODE_SIZE = 32;
const HIGHEST_BIT = 0x80000000;
// Quantum BIP32 version bytes (using 360' as per specification)
const QUANTUM_BIP32_VERSION = {
    public: 0x04889b21, // Custom version for quantum public keys
    private: 0x04889ade, // Custom version for quantum private keys
};
/**
 * Quantum signer implementation using ML-DSA-87
 */
class QuantumBip32Signer {
    _privateKey;
    _publicKey;
    constructor(_privateKey, _publicKey) {
        this._privateKey = _privateKey;
        this._publicKey = _publicKey;
    }
    get publicKey() {
        if (!this._publicKey) {
            throw new Error('Public key not available');
        }
        return this._publicKey;
    }
    get privateKey() {
        return this._privateKey;
    }
    sign(hash) {
        if (!this._privateKey) {
            throw new Error('Missing private key');
        }
        // ML-DSA-87 signature with extra entropy for enhanced security
        // The @btc-vision/post-quantum library requires extraEntropy for security
        const signature = ml_dsa_js_1.ml_dsa87.sign(hash, this._privateKey, {
            extraEntropy: (0, utils_js_1.randomBytes)(32),
        });
        return signature;
    }
    verify(hash, signature) {
        return ml_dsa_js_1.ml_dsa87.verify(signature, hash, this._publicKey);
    }
}
/**
 * Quantum BIP32 implementation using ML-DSA-87
 * Uses BIP32 for hierarchical seed derivation, then ML-DSA-87 for key generation
 */
class QuantumBIP32 extends QuantumBip32Signer {
    chainCode;
    _depth;
    _index;
    _parentFingerprint;
    constructor(_privateKey, _publicKey, chainCode, _depth = 0, _index = 0, _parentFingerprint = 0x00000000) {
        super(_privateKey, _publicKey);
        this.chainCode = chainCode;
        this._depth = _depth;
        this._index = _index;
        this._parentFingerprint = _parentFingerprint;
    }
    get depth() {
        return this._depth;
    }
    get index() {
        return this._index;
    }
    get parentFingerprint() {
        return this._parentFingerprint;
    }
    get identifier() {
        return crypto.hash160(this.publicKey);
    }
    get fingerprint() {
        return this.identifier.slice(0, 4);
    }
    isNeutered() {
        return this._privateKey === undefined;
    }
    neutered() {
        return new QuantumBIP32(undefined, this.publicKey, this.chainCode, this.depth, this.index, this.parentFingerprint);
    }
    toBase58() {
        const version = !this.isNeutered()
            ? QUANTUM_BIP32_VERSION.private
            : QUANTUM_BIP32_VERSION.public;
        const isPrivate = !this.isNeutered();
        const keySize = isPrivate
            ? MLDSA87_PRIVATE_KEY_SIZE
            : MLDSA87_PUBLIC_KEY_SIZE;
        // Buffer structure:
        // 4 bytes: version
        // 1 byte: depth
        // 4 bytes: parent fingerprint
        // 4 bytes: child index
        // 32 bytes: chain code
        // 4896 or 2592 bytes: key data
        const bufferSize = 4 + 1 + 4 + 4 + 32 + keySize;
        const buffer = new Uint8Array(bufferSize);
        let offset = 0;
        // Version
        tools.writeUInt32(buffer, offset, version, 'BE');
        offset += 4;
        // Depth
        tools.writeUInt8(buffer, offset, this.depth);
        offset += 1;
        // Parent fingerprint
        tools.writeUInt32(buffer, offset, this.parentFingerprint, 'BE');
        offset += 4;
        // Child index
        tools.writeUInt32(buffer, offset, this.index, 'BE');
        offset += 4;
        // Chain code
        buffer.set(this.chainCode, offset);
        offset += 32;
        // Key data
        if (isPrivate) {
            buffer.set(this._privateKey, offset);
        }
        else {
            buffer.set(this._publicKey, offset);
        }
        return bs58check.encode(buffer);
    }
    /**
     * Derive a child key using BIP32 HMAC chain for seed derivation,
     * then ML-DSA-87 for key generation
     */
    derive(index) {
        v.parse(types_js_1.Uint32Schema, index);
        // ML-DSA-87 cannot derive child keys without the private key
        // Unlike EC crypto, you cannot do public key only derivation
        if (this.isNeutered()) {
            throw new TypeError('Cannot derive child keys without private key');
        }
        const isHardened = index >= HIGHEST_BIT;
        let data;
        // Hardened child
        if (isHardened) {
            // For ML-DSA-87, we use a hash of the private key for derivation data
            // since the private key is too large (4896 bytes)
            const privateKeyHash = crypto.hash256(this._privateKey);
            data = new Uint8Array(1 + 32 + 4);
            data[0] = 0x00;
            data.set(privateKeyHash, 1);
            tools.writeUInt32(data, 33, index, 'BE');
        }
        else {
            // Normal child - still needs private key for ML-DSA-87
            // Use hash of private key (not public key like EC)
            const privateKeyHash = crypto.hash256(this._privateKey);
            data = new Uint8Array(32 + 4);
            data.set(privateKeyHash, 0);
            tools.writeUInt32(data, 32, index, 'BE');
        }
        // Derive 512-bit seed using HMAC-SHA512
        const I = crypto.hmacSHA512(this.chainCode, data);
        const IL = I.slice(0, 32); // 256 bits for key generation seed
        const IR = I.slice(32); // 256 bits for new chain code
        // Use IL as entropy for ML-DSA-87 key generation
        // IL is already 32 bytes (256 bits), which is the required seed size
        // Generate ML-DSA-87 key pair from seed
        const { secretKey: privateKey, publicKey } = ml_dsa_js_1.ml_dsa87.keygen(IL);
        return new QuantumBIP32(privateKey, publicKey, IR, this.depth + 1, index, tools.readUInt32(this.fingerprint, 0, 'BE'));
    }
    deriveHardened(index) {
        try {
            v.parse(types_js_1.Uint31Schema, index);
        }
        catch (e) {
            throw new TypeError('Expected UInt31, got ' + index);
        }
        return this.derive(index + HIGHEST_BIT);
    }
    derivePath(path) {
        v.parse(types_js_1.Bip32PathSchema, path);
        let splitPath = path.split('/');
        if (splitPath[0] === 'm') {
            if (this.parentFingerprint) {
                throw new TypeError('Expected master, got child');
            }
            splitPath = splitPath.slice(1);
        }
        return splitPath.reduce((prevHd, indexStr) => {
            let index;
            if (indexStr.slice(-1) === `'`) {
                index = parseInt(indexStr.slice(0, -1), 10);
                return prevHd.deriveHardened(index);
            }
            else {
                index = parseInt(indexStr, 10);
                return prevHd.derive(index);
            }
        }, this);
    }
}
/**
 * Create a quantum BIP32 master key from a seed
 */
function fromSeed(seed) {
    v.parse(v.instance(Uint8Array), seed);
    if (seed.length < 16) {
        throw new TypeError('Seed should be at least 128 bits');
    }
    if (seed.length > 64) {
        throw new TypeError('Seed should be at most 512 bits');
    }
    // Use BIP32 standard HMAC for initial seed derivation
    const I = crypto.hmacSHA512(tools.fromUtf8('Bitcoin seed'), seed);
    const IL = I.slice(0, 32);
    const IR = I.slice(32);
    // IL is 32 bytes (256 bits), which is the required seed size for ML-DSA-87
    // Generate ML-DSA-87 master key pair
    const { secretKey: privateKey, publicKey } = ml_dsa_js_1.ml_dsa87.keygen(IL);
    return new QuantumBIP32(privateKey, publicKey, IR, // Chain code
    0, // depth
    0, // index
    0);
}
/**
 * Import a quantum key from base58
 */
function fromBase58(inString) {
    const buffer = bs58check.decode(inString);
    // Read version
    const version = tools.readUInt32(buffer, 0, 'BE');
    const isPrivate = version === QUANTUM_BIP32_VERSION.private;
    const isPublic = version === QUANTUM_BIP32_VERSION.public;
    if (!isPrivate && !isPublic) {
        throw new TypeError('Invalid quantum BIP32 version');
    }
    const expectedSize = isPrivate
        ? 4 + 1 + 4 + 4 + 32 + MLDSA87_PRIVATE_KEY_SIZE
        : 4 + 1 + 4 + 4 + 32 + MLDSA87_PUBLIC_KEY_SIZE;
    if (buffer.length !== expectedSize) {
        throw new TypeError(`Invalid buffer length: expected ${expectedSize}, got ${buffer.length}`);
    }
    let offset = 4;
    // Depth
    const depth = buffer[offset];
    offset += 1;
    // Parent fingerprint
    const parentFingerprint = tools.readUInt32(buffer, offset, 'BE');
    if (depth === 0 && parentFingerprint !== 0x00000000) {
        throw new TypeError('Invalid parent fingerprint');
    }
    offset += 4;
    // Child index
    const index = tools.readUInt32(buffer, offset, 'BE');
    if (depth === 0 && index !== 0) {
        throw new TypeError('Invalid index');
    }
    offset += 4;
    // Chain code
    const chainCode = buffer.slice(offset, offset + 32);
    offset += 32;
    // Key data
    if (isPrivate) {
        const privateKey = buffer.slice(offset, offset + MLDSA87_PRIVATE_KEY_SIZE);
        // Derive public key from private key (getPublicKey returns secretKey, so we need the publicKey part)
        const publicKey = ml_dsa_js_1.ml_dsa87.getPublicKey(privateKey);
        return new QuantumBIP32(privateKey, publicKey, chainCode, depth, index, parentFingerprint);
    }
    else {
        const publicKey = buffer.slice(offset, offset + MLDSA87_PUBLIC_KEY_SIZE);
        return new QuantumBIP32(undefined, publicKey, chainCode, depth, index, parentFingerprint);
    }
}
/**
 * Create quantum key from public key and chain code
 */
function fromPublicKey(publicKey, chainCode) {
    if (publicKey.length !== MLDSA87_PUBLIC_KEY_SIZE) {
        throw new TypeError(`Invalid public key length: expected ${MLDSA87_PUBLIC_KEY_SIZE}, got ${publicKey.length}`);
    }
    if (chainCode.length !== CHAIN_CODE_SIZE) {
        throw new TypeError(`Invalid chain code length: expected ${CHAIN_CODE_SIZE}, got ${chainCode.length}`);
    }
    return new QuantumBIP32(undefined, publicKey, chainCode, 0, 0, 0);
}
/**
 * Create quantum key from private key and chain code
 */
function fromPrivateKey(privateKey, chainCode) {
    if (privateKey.length !== MLDSA87_PRIVATE_KEY_SIZE) {
        throw new TypeError(`Invalid private key length: expected ${MLDSA87_PRIVATE_KEY_SIZE}, got ${privateKey.length}`);
    }
    if (chainCode.length !== CHAIN_CODE_SIZE) {
        throw new TypeError(`Invalid chain code length: expected ${CHAIN_CODE_SIZE}, got ${chainCode.length}`);
    }
    // Derive public key from private key
    const publicKey = ml_dsa_js_1.ml_dsa87.getPublicKey(privateKey);
    return new QuantumBIP32(privateKey, publicKey, chainCode, 0, 0, 0);
}
/**
 * Quantum BIP32 Factory
 * Provides API for creating and managing ML-DSA-87 hierarchical deterministic keys
 */
exports.QuantumBIP32Factory = {
    fromSeed,
    fromBase58,
    fromPublicKey,
    fromPrivateKey,
};
