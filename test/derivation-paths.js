import tape from 'tape';
import {
  DerivationPath,
  QuantumDerivationPath,
  getQuantumPath,
  getBitcoinPath
} from '../src/esm/derivation-paths.js';

tape('DerivationPath enum', (t) => {
  t.test('contains standard Bitcoin paths', (t) => {
    t.equal(DerivationPath.BIP44, "m/44'/0'/0'/0/0");
    t.equal(DerivationPath.BIP49, "m/49'/0'/0'/0/0");
    t.equal(DerivationPath.BIP84, "m/84'/0'/0'/0/0");
    t.equal(DerivationPath.BIP86, "m/86'/0'/0'/0/0");
    t.equal(DerivationPath.BIP360, "m/360'/0'/0'/0/0");
    t.end();
  });

  t.end();
});

tape('QuantumDerivationPath enum', (t) => {
  t.test('contains quantum-specific paths', (t) => {
    t.equal(QuantumDerivationPath.STANDARD, "m/360'/0'/0'/0/0");
    t.equal(QuantumDerivationPath.CHANGE, "m/360'/0'/0'/1/0");
    t.equal(QuantumDerivationPath.ACCOUNT_0_ADDRESS_0, "m/360'/0'/0'/0/0");
    t.equal(QuantumDerivationPath.ACCOUNT_0_ADDRESS_1, "m/360'/0'/0'/0/1");
    t.equal(QuantumDerivationPath.ACCOUNT_1_ADDRESS_0, "m/360'/1'/0'/0/0");
    t.end();
  });

  t.end();
});

tape('getQuantumPath', (t) => {
  t.test('generates default path', (t) => {
    const path = getQuantumPath();
    t.equal(path, "m/360'/0'/0'/0");
    t.end();
  });

  t.test('generates path with account index', (t) => {
    const path = getQuantumPath(1);
    t.equal(path, "m/360'/1'/0'/0");
    t.end();
  });

  t.test('generates path with address index', (t) => {
    const path = getQuantumPath(0, 5);
    t.equal(path, "m/360'/0'/0'/5");
    t.end();
  });

  t.test('generates change address path', (t) => {
    const path = getQuantumPath(0, 0, true);
    t.equal(path, "m/360'/0'/1'/0");
    t.end();
  });

  t.test('generates path with all custom parameters', (t) => {
    const path = getQuantumPath(2, 10, true);
    t.equal(path, "m/360'/2'/1'/10");
    t.end();
  });

  t.end();
});

tape('getBitcoinPath', (t) => {
  t.test('generates BIP44 path with defaults', (t) => {
    const path = getBitcoinPath(44);
    t.equal(path, "m/44'/0'/0'/0/0");
    t.end();
  });

  t.test('generates BIP49 path', (t) => {
    const path = getBitcoinPath(49);
    t.equal(path, "m/49'/0'/0'/0/0");
    t.end();
  });

  t.test('generates BIP84 path', (t) => {
    const path = getBitcoinPath(84);
    t.equal(path, "m/84'/0'/0'/0/0");
    t.end();
  });

  t.test('generates BIP86 path', (t) => {
    const path = getBitcoinPath(86);
    t.equal(path, "m/86'/0'/0'/0/0");
    t.end();
  });

  t.test('generates path with account index', (t) => {
    const path = getBitcoinPath(44, 1);
    t.equal(path, "m/44'/0'/1'/0/0");
    t.end();
  });

  t.test('generates path with address index', (t) => {
    const path = getBitcoinPath(44, 0, 5);
    t.equal(path, "m/44'/0'/0'/0/5");
    t.end();
  });

  t.test('generates change address path', (t) => {
    const path = getBitcoinPath(44, 0, 0, true);
    t.equal(path, "m/44'/0'/0'/1/0");
    t.end();
  });

  t.test('generates path with all custom parameters', (t) => {
    const path = getBitcoinPath(84, 2, 10, true);
    t.equal(path, "m/84'/0'/2'/1/10");
    t.end();
  });

  t.end();
});
