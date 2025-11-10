import { QuantumBIP32Factory } from '../src/esm/index.js';
import tape from 'tape';
import * as tools from 'uint8array-tools';
import { base58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';

const _bs58check = base58check(sha256);
const bs58check = {
  encode: (data) => _bs58check.encode(data),
  decode: (str) => _bs58check.decode(str),
};

tape('QuantumBIP32Factory.fromSeed', (t) => {
  t.test('creates master key from valid seed', (t) => {
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const master = QuantumBIP32Factory.fromSeed(seed);

    t.equal(master.depth, 0);
    t.equal(master.index, 0);
    t.equal(master.parentFingerprint, 0);
    t.equal(master.publicKey.length, 2592);
    t.equal(master.privateKey.length, 4896);
    t.equal(master.chainCode.length, 32);
    t.equal(master.isNeutered(), false);
    t.end();
  });

  t.test('throws on seed too short', (t) => {
    const seed = new Uint8Array(15);
    t.throws(() => QuantumBIP32Factory.fromSeed(seed), /Seed should be at least 128 bits/);
    t.end();
  });

  t.test('throws on seed too long', (t) => {
    const seed = new Uint8Array(65);
    t.throws(() => QuantumBIP32Factory.fromSeed(seed), /Seed should be at most 512 bits/);
    t.end();
  });

  t.test('produces deterministic keys from same seed', (t) => {
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const master1 = QuantumBIP32Factory.fromSeed(seed);
    const master2 = QuantumBIP32Factory.fromSeed(seed);

    t.equal(tools.toHex(master1.publicKey), tools.toHex(master2.publicKey));
    t.equal(tools.toHex(master1.privateKey), tools.toHex(master2.privateKey));
    t.equal(tools.toHex(master1.chainCode), tools.toHex(master2.chainCode));
    t.end();
  });

  t.end();
});

tape('QuantumBIP32 derivation', (t) => {
  const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const master = QuantumBIP32Factory.fromSeed(seed);

  t.test('derive hardened child', (t) => {
    const child = master.deriveHardened(0);

    t.equal(child.depth, 1);
    t.equal(child.index, 0x80000000);
    t.equal(child.publicKey.length, 2592);
    t.equal(child.privateKey.length, 4896);
    t.notEqual(tools.toHex(child.publicKey), tools.toHex(master.publicKey));
    t.end();
  });

  t.test('derive normal child', (t) => {
    const child = master.derive(0);

    t.equal(child.depth, 1);
    t.equal(child.index, 0);
    t.equal(child.publicKey.length, 2592);
    t.equal(child.privateKey.length, 4896);
    t.end();
  });

  t.test('derivePath with hardened path', (t) => {
    const child = master.derivePath("m/360'/0'/0'/0/0");

    t.equal(child.depth, 5);
    t.equal(child.index, 0);
    t.ok(child.privateKey);
    t.end();
  });

  t.test('derivePath from child (not master)', (t) => {
    const child1 = master.deriveHardened(360);
    const child2 = child1.derivePath("0'/0'/0/0");

    t.equal(child2.depth, 5);
    t.end();
  });

  t.test('throws on derivePath with m prefix on child', (t) => {
    const child = master.deriveHardened(360);
    t.throws(() => child.derivePath("m/0'/0'/0"), /Expected master, got child/);
    t.end();
  });

  t.test('produces deterministic child keys', (t) => {
    const child1 = master.derivePath("m/360'/0'/0'/0/0");
    const child2 = master.derivePath("m/360'/0'/0'/0/0");

    t.equal(tools.toHex(child1.publicKey), tools.toHex(child2.publicKey));
    t.equal(tools.toHex(child1.privateKey), tools.toHex(child2.privateKey));
    t.end();
  });

  t.test('different paths produce different keys', (t) => {
    const child1 = master.derivePath("m/360'/0'/0'/0/0");
    const child2 = master.derivePath("m/360'/0'/0'/0/1");

    t.notEqual(tools.toHex(child1.publicKey), tools.toHex(child2.publicKey));
    t.end();
  });

  t.test('derive validates index bounds', (t) => {
    t.throws(() => master.derive(-1));
    t.throws(() => master.derive(0x100000000));
    t.end();
  });

  t.test('deriveHardened validates index bounds', (t) => {
    t.throws(() => master.deriveHardened(-1), /Expected UInt31/);
    t.throws(() => master.deriveHardened(0x80000000), /Expected UInt31/);
    t.end();
  });

  t.test('deriveHardened throws on non-number input', (t) => {
    t.throws(() => master.deriveHardened('notanumber'), /Expected UInt31/);
    t.end();
  });

  t.end();
});

tape('QuantumBIP32 neutered keys', (t) => {
  const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const master = QuantumBIP32Factory.fromSeed(seed);

  t.test('neutered removes private key', (t) => {
    const neutered = master.neutered();

    t.equal(neutered.isNeutered(), true);
    t.equal(neutered.privateKey, undefined);
    t.equal(tools.toHex(neutered.publicKey), tools.toHex(master.publicKey));
    t.equal(tools.toHex(neutered.chainCode), tools.toHex(master.chainCode));
    t.end();
  });

  t.test('neutered key cannot sign', (t) => {
    const neutered = master.neutered();
    const message = new Uint8Array(32);

    t.throws(() => neutered.sign(message), /Missing private key/);
    t.end();
  });

  t.test('neutered key can verify', (t) => {
    const message = new Uint8Array(32);
    message.fill(0x42);
    const signature = master.sign(message);
    const neutered = master.neutered();

    t.equal(neutered.verify(message, signature), true);
    t.end();
  });

  t.test('neutered key cannot derive any children', (t) => {
    const neutered = master.neutered();

    // ML-DSA-87 cannot derive children without private key (unlike EC)
    t.throws(() => neutered.derive(0), /Cannot derive child keys without private key/);
    t.throws(() => neutered.derive(0x80000000), /Cannot derive child keys without private key/);
    t.throws(() => neutered.deriveHardened(0), /Cannot derive child keys without private key/);
    t.end();
  });

  t.end();
});

tape('QuantumBIP32 signing and verification', (t) => {
  const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const master = QuantumBIP32Factory.fromSeed(seed);

  t.test('sign produces valid signature', (t) => {
    const message = new Uint8Array(32);
    message.fill(0x42);
    const signature = master.sign(message);

    t.equal(signature.length, 4627);
    t.equal(master.verify(message, signature), true);
    t.end();
  });

  t.test('verify rejects invalid signature', (t) => {
    const message = new Uint8Array(32);
    message.fill(0x42);
    const signature = master.sign(message);
    signature[0] ^= 0x01; // Corrupt signature

    t.equal(master.verify(message, signature), false);
    t.end();
  });

  t.test('verify rejects wrong message', (t) => {
    const message1 = new Uint8Array(32);
    message1.fill(0x42);
    const message2 = new Uint8Array(32);
    message2.fill(0x43);
    const signature = master.sign(message1);

    t.equal(master.verify(message2, signature), false);
    t.end();
  });

  t.test('sign throws without private key', (t) => {
    const neutered = master.neutered();
    const message = new Uint8Array(32);

    t.throws(() => neutered.sign(message), /Missing private key/);
    t.end();
  });

  t.test('signatures are non-deterministic (include entropy)', (t) => {
    const message = new Uint8Array(32);
    message.fill(0x42);
    const sig1 = master.sign(message);
    const sig2 = master.sign(message);

    // Signatures should differ due to randomness
    t.notEqual(tools.toHex(sig1), tools.toHex(sig2));

    // But both should verify
    t.equal(master.verify(message, sig1), true);
    t.equal(master.verify(message, sig2), true);
    t.end();
  });

  t.end();
});

tape('QuantumBIP32 base58 import/export', (t) => {
  const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const master = QuantumBIP32Factory.fromSeed(seed);

  t.test('export and import private key', (t) => {
    const exported = master.toBase58();
    const imported = QuantumBIP32Factory.fromBase58(exported);

    t.equal(tools.toHex(imported.publicKey), tools.toHex(master.publicKey));
    t.equal(tools.toHex(imported.privateKey), tools.toHex(master.privateKey));
    t.equal(tools.toHex(imported.chainCode), tools.toHex(master.chainCode));
    t.equal(imported.depth, master.depth);
    t.equal(imported.index, master.index);
    t.equal(imported.parentFingerprint, master.parentFingerprint);
    t.end();
  });

  t.test('export and import public key', (t) => {
    const neutered = master.neutered();
    const exported = neutered.toBase58();
    const imported = QuantumBIP32Factory.fromBase58(exported);

    t.equal(tools.toHex(imported.publicKey), tools.toHex(neutered.publicKey));
    t.equal(imported.privateKey, undefined);
    t.equal(imported.isNeutered(), true);
    t.end();
  });

  t.test('imported key can sign', (t) => {
    const exported = master.toBase58();
    const imported = QuantumBIP32Factory.fromBase58(exported);
    const message = new Uint8Array(32);
    message.fill(0x42);

    const signature = imported.sign(message);
    // Verify with imported key's own verify (they have same keys)
    t.equal(imported.verify(message, signature), true);
    t.end();
  });

  t.test('throws on invalid base58', (t) => {
    t.throws(() => QuantumBIP32Factory.fromBase58('invalid'));
    t.end();
  });

  t.test('throws on invalid version', (t) => {
    // Create a base58 string with invalid version bytes
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const key = QuantumBIP32Factory.fromSeed(seed);
    const validB58 = key.toBase58();

    // Decode, corrupt version, re-encode
    const decoded = bs58check.decode(validB58);
    decoded[0] = 0xFF; // Invalid version byte
    const corrupted = bs58check.encode(decoded);

    t.throws(() => QuantumBIP32Factory.fromBase58(corrupted), /Invalid quantum BIP32 version/);
    t.end();
  });

  t.test('throws on invalid buffer length', (t) => {
    // Create a base58 with wrong length
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const key = QuantumBIP32Factory.fromSeed(seed);
    const validB58 = key.toBase58();

    // Decode, truncate, re-encode
    const decoded = bs58check.decode(validB58);
    const truncated = decoded.slice(0, 100);
    const corrupted = bs58check.encode(truncated);

    t.throws(() => QuantumBIP32Factory.fromBase58(corrupted), /Invalid buffer length/);
    t.end();
  });

  t.test('throws on invalid parent fingerprint for master', (t) => {
    // Create a base58 with depth=0 but non-zero parent fingerprint
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const key = QuantumBIP32Factory.fromSeed(seed);
    const validB58 = key.toBase58();

    const decoded = bs58check.decode(validB58);
    // depth is at offset 4, set to 0
    decoded[4] = 0;
    // parent fingerprint is at offset 5-8, set to non-zero
    decoded[5] = 0x12;
    decoded[6] = 0x34;
    decoded[7] = 0x56;
    decoded[8] = 0x78;

    const corrupted = bs58check.encode(decoded);

    t.throws(() => QuantumBIP32Factory.fromBase58(corrupted), /Invalid parent fingerprint/);
    t.end();
  });

  t.test('throws on invalid index for master', (t) => {
    // Create a base58 with depth=0 but non-zero index
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const key = QuantumBIP32Factory.fromSeed(seed);
    const validB58 = key.toBase58();

    const decoded = bs58check.decode(validB58);
    // depth is at offset 4, set to 0
    decoded[4] = 0;
    // parent fingerprint at offset 5-8, keep at 0
    decoded[5] = 0;
    decoded[6] = 0;
    decoded[7] = 0;
    decoded[8] = 0;
    // index is at offset 9-12, set to non-zero
    decoded[9] = 0;
    decoded[10] = 0;
    decoded[11] = 0;
    decoded[12] = 1;

    const corrupted = bs58check.encode(decoded);

    t.throws(() => QuantumBIP32Factory.fromBase58(corrupted), /Invalid index/);
    t.end();
  });

  t.test('child key export includes correct metadata', (t) => {
    const child = master.derivePath("m/360'/0'/0'/0/0");
    const exported = child.toBase58();
    const imported = QuantumBIP32Factory.fromBase58(exported);

    t.equal(imported.depth, 5);
    t.equal(imported.index, 0);
    t.notEqual(imported.parentFingerprint, 0);
    t.end();
  });

  t.end();
});

tape('QuantumBIP32Factory.fromPublicKey', (t) => {
  const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const master = QuantumBIP32Factory.fromSeed(seed);

  t.test('creates key from public key and chain code', (t) => {
    const key = QuantumBIP32Factory.fromPublicKey(master.publicKey, master.chainCode);

    t.equal(tools.toHex(key.publicKey), tools.toHex(master.publicKey));
    t.equal(tools.toHex(key.chainCode), tools.toHex(master.chainCode));
    t.equal(key.privateKey, undefined);
    t.equal(key.isNeutered(), true);
    t.end();
  });

  t.test('throws on invalid public key length', (t) => {
    const invalidPubKey = new Uint8Array(100);
    const chainCode = new Uint8Array(32);

    t.throws(() => QuantumBIP32Factory.fromPublicKey(invalidPubKey, chainCode), /Invalid public key length/);
    t.end();
  });

  t.test('throws on invalid chain code length', (t) => {
    const invalidChainCode = new Uint8Array(16);

    t.throws(() => QuantumBIP32Factory.fromPublicKey(master.publicKey, invalidChainCode), /Invalid chain code length/);
    t.end();
  });

  t.end();
});

tape('QuantumBIP32Factory.fromPrivateKey', (t) => {
  const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const master = QuantumBIP32Factory.fromSeed(seed);

  t.test('creates key from private key and chain code', (t) => {
    const key = QuantumBIP32Factory.fromPrivateKey(master.privateKey, master.chainCode);

    t.equal(tools.toHex(key.privateKey), tools.toHex(master.privateKey));
    t.equal(tools.toHex(key.publicKey), tools.toHex(master.publicKey));
    t.equal(tools.toHex(key.chainCode), tools.toHex(master.chainCode));
    t.equal(key.isNeutered(), false);
    t.end();
  });

  t.test('throws on invalid private key length', (t) => {
    const invalidPrivKey = new Uint8Array(100);
    const chainCode = new Uint8Array(32);

    t.throws(() => QuantumBIP32Factory.fromPrivateKey(invalidPrivKey, chainCode), /Invalid private key length/);
    t.end();
  });

  t.test('throws on invalid chain code length', (t) => {
    const invalidChainCode = new Uint8Array(16);

    t.throws(() => QuantumBIP32Factory.fromPrivateKey(master.privateKey, invalidChainCode), /Invalid chain code length/);
    t.end();
  });

  t.end();
});

tape('QuantumBIP32 identifier and fingerprint', (t) => {
  const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
  const master = QuantumBIP32Factory.fromSeed(seed);

  t.test('identifier is 20 bytes', (t) => {
    t.equal(master.identifier.length, 20);
    t.end();
  });

  t.test('fingerprint is first 4 bytes of identifier', (t) => {
    t.equal(master.fingerprint.length, 4);
    t.equal(tools.toHex(master.fingerprint), tools.toHex(master.identifier.slice(0, 4)));
    t.end();
  });

  t.test('child has non-zero parent fingerprint', (t) => {
    const child = master.deriveHardened(0);
    t.notEqual(child.parentFingerprint, 0);

    // Parent fingerprint is stored as a number, convert to compare
    const parentFingerprintBuffer = new Uint8Array(4);
    const view = new DataView(parentFingerprintBuffer.buffer);
    view.setUint32(0, child.parentFingerprint, false); // Big-endian

    t.equal(tools.toHex(parentFingerprintBuffer), tools.toHex(master.fingerprint));
    t.end();
  });

  t.test('master has zero parent fingerprint', (t) => {
    t.equal(master.parentFingerprint, 0);
    t.end();
  });

  t.end();
});

tape('QuantumBIP32 edge cases', (t) => {
  t.test('can derive index 0', (t) => {
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const master = QuantumBIP32Factory.fromSeed(seed);
    const child = master.derive(0);

    t.equal(child.index, 0);
    t.end();
  });

  t.test('can derive max non-hardened index', (t) => {
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const master = QuantumBIP32Factory.fromSeed(seed);
    const child = master.derive(0x7fffffff);

    t.equal(child.index, 0x7fffffff);
    t.end();
  });

  t.test('can derive max hardened index', (t) => {
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const master = QuantumBIP32Factory.fromSeed(seed);
    const child = master.derive(0xffffffff);

    t.equal(child.index, 0xffffffff);
    t.end();
  });

  t.test('derivePath handles various formats', (t) => {
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const master = QuantumBIP32Factory.fromSeed(seed);

    t.doesNotThrow(() => master.derivePath("m/0"));
    t.doesNotThrow(() => master.derivePath("m/0'"));
    t.doesNotThrow(() => master.derivePath("m/0'/1"));
    t.doesNotThrow(() => master.derivePath("m/0'/1/2'/3"));
    t.end();
  });

  t.test('very deep derivation path', (t) => {
    const seed = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const master = QuantumBIP32Factory.fromSeed(seed);
    const deep = master.derivePath("m/0'/1'/2'/3'/4'/5'/6'/7'/8'/9'");

    t.equal(deep.depth, 10);
    t.end();
  });

  t.end();
});

tape('QuantumBIP32 compatibility', (t) => {
  t.test('same seed produces same keys across instances', (t) => {
    const seed = tools.fromHex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
    const master1 = QuantumBIP32Factory.fromSeed(seed);
    const master2 = QuantumBIP32Factory.fromSeed(seed);

    const child1 = master1.derivePath("m/360'/0'/0'/0/0");
    const child2 = master2.derivePath("m/360'/0'/0'/0/0");

    t.equal(tools.toHex(child1.privateKey), tools.toHex(child2.privateKey));
    t.equal(tools.toHex(child1.publicKey), tools.toHex(child2.publicKey));
    t.end();
  });

  t.test('different seeds produce different keys', (t) => {
    const seed1 = tools.fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    const seed2 = tools.fromHex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
    const master1 = QuantumBIP32Factory.fromSeed(seed1);
    const master2 = QuantumBIP32Factory.fromSeed(seed2);

    t.notEqual(tools.toHex(master1.publicKey), tools.toHex(master2.publicKey));
    t.end();
  });

  t.test('16 byte seed works', (t) => {
    const seed = new Uint8Array(16);
    seed.fill(0x42);
    t.doesNotThrow(() => QuantumBIP32Factory.fromSeed(seed));
    t.end();
  });

  t.test('64 byte seed works', (t) => {
    const seed = new Uint8Array(64);
    seed.fill(0x42);
    t.doesNotThrow(() => QuantumBIP32Factory.fromSeed(seed));
    t.end();
  });

  t.end();
});
