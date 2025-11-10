"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QuantumBIP32Factory = exports.BIP32Factory = exports.default = void 0;
var bip32_js_1 = require("./bip32.cjs");
Object.defineProperty(exports, "default", { enumerable: true, get: function () { return bip32_js_1.BIP32Factory; } });
Object.defineProperty(exports, "BIP32Factory", { enumerable: true, get: function () { return bip32_js_1.BIP32Factory; } });
// Quantum-resistant BIP32 using ML-DSA-87
var index_js_1 = require("./quantum/index.cjs");
Object.defineProperty(exports, "QuantumBIP32Factory", { enumerable: true, get: function () { return index_js_1.QuantumBIP32Factory; } });
