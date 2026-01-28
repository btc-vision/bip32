import { describe, it, expect } from 'vitest';
import {
  DerivationPath,
  QuantumDerivationPath,
  getQuantumPath,
  getBitcoinPath
} from '../src/esm/derivation-paths.js';

describe('DerivationPath enum', () => {
  it('contains standard Bitcoin paths', () => {
    expect(DerivationPath.BIP44).toBe("m/44'/0'/0'/0/0");
    expect(DerivationPath.BIP49).toBe("m/49'/0'/0'/0/0");
    expect(DerivationPath.BIP84).toBe("m/84'/0'/0'/0/0");
    expect(DerivationPath.BIP86).toBe("m/86'/0'/0'/0/0");
    expect(DerivationPath.BIP360).toBe("m/360'/0'/0'/0/0");
  });
});

describe('QuantumDerivationPath enum', () => {
  it('contains quantum-specific paths', () => {
    expect(QuantumDerivationPath.STANDARD).toBe("m/360'/0'/0'/0/0");
    expect(QuantumDerivationPath.CHANGE).toBe("m/360'/0'/0'/1/0");
    expect(QuantumDerivationPath.ACCOUNT_0_ADDRESS_0).toBe("m/360'/0'/0'/0/0");
    expect(QuantumDerivationPath.ACCOUNT_0_ADDRESS_1).toBe("m/360'/0'/0'/0/1");
    expect(QuantumDerivationPath.ACCOUNT_1_ADDRESS_0).toBe("m/360'/1'/0'/0/0");
  });
});

describe('getQuantumPath', () => {
  it('generates default path', () => {
    const path = getQuantumPath();
    expect(path).toBe("m/360'/0'/0'/0");
  });

  it('generates path with account index', () => {
    const path = getQuantumPath(1);
    expect(path).toBe("m/360'/1'/0'/0");
  });

  it('generates path with address index', () => {
    const path = getQuantumPath(0, 5);
    expect(path).toBe("m/360'/0'/0'/5");
  });

  it('generates change address path', () => {
    const path = getQuantumPath(0, 0, true);
    expect(path).toBe("m/360'/0'/1'/0");
  });

  it('generates path with all custom parameters', () => {
    const path = getQuantumPath(2, 10, true);
    expect(path).toBe("m/360'/2'/1'/10");
  });
});

describe('getBitcoinPath', () => {
  it('generates BIP44 path with defaults', () => {
    const path = getBitcoinPath(44);
    expect(path).toBe("m/44'/0'/0'/0/0");
  });

  it('generates BIP49 path', () => {
    const path = getBitcoinPath(49);
    expect(path).toBe("m/49'/0'/0'/0/0");
  });

  it('generates BIP84 path', () => {
    const path = getBitcoinPath(84);
    expect(path).toBe("m/84'/0'/0'/0/0");
  });

  it('generates BIP86 path', () => {
    const path = getBitcoinPath(86);
    expect(path).toBe("m/86'/0'/0'/0/0");
  });

  it('generates path with account index', () => {
    const path = getBitcoinPath(44, 1);
    expect(path).toBe("m/44'/0'/1'/0/0");
  });

  it('generates path with address index', () => {
    const path = getBitcoinPath(44, 0, 5);
    expect(path).toBe("m/44'/0'/0'/0/5");
  });

  it('generates change address path', () => {
    const path = getBitcoinPath(44, 0, 0, true);
    expect(path).toBe("m/44'/0'/0'/1/0");
  });

  it('generates path with all custom parameters', () => {
    const path = getBitcoinPath(84, 2, 10, true);
    expect(path).toBe("m/84'/0'/2'/1/10");
  });
});
