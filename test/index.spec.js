import BIP32Creator from '../src/esm/index.js'
import { describe, it, expect } from 'vitest'
import fixtures from './fixtures/index.json' with { type: "json" }
const { valid, invalid } = fixtures
import * as ecc from "tiny-secp256k1";
import * as tools from "uint8array-tools";
const BIP32 = BIP32Creator(ecc)
let LITECOIN = {
  messagePrefix: '\x19Litecoin Signed Message:\n',
  bech32: 'ltc',
  pubKeyHash: 0x30,
  scriptHash: 0x32,
  wif: 0xb0,
  bip32: {
    public: 0x019da462,
    private: 0x019d9cfe
  }
}

// TODO: amend the JSON
let validAll = []
  valid.forEach((f) => {
  f.master.network = f.network
  f.master.children = f.children
  f.master.comment = f.comment
  f.children.forEach((fc) => {
    fc.network = f.network
    validAll.push(fc)
  })
  delete f.children
  validAll.push(f.master)
})

function verify (hd, prv, f, network) {
  expect(tools.toHex(hd.chainCode)).toBe(f.chainCode)
  expect(hd.depth).toBe(f.depth >>> 0)
  expect(hd.index).toBe(f.index >>> 0)
  expect(hd.compressed).toBe(true)
  expect(tools.toHex(hd.fingerprint)).toBe(f.fingerprint)
  expect(tools.toHex(hd.identifier)).toBe(f.identifier)
  expect(tools.toHex(hd.publicKey)).toBe(f.pubKey)
  if (prv) expect(hd.toBase58()).toBe(f.base58Priv)
  if (prv) expect(tools.toHex(hd.privateKey)).toBe(f.privKey)
  if (prv) expect(hd.toWIF()).toBe(f.wif)
  if (!prv) expect(() => hd.toWIF()).toThrow(/Missing private key/)
  if (!prv) expect(hd.privateKey).toBe(undefined)
  expect(hd.neutered().toBase58()).toBe(f.base58)
  expect(hd.isNeutered()).toBe(!prv)

  if (!f.children) return
  if (!prv && f.children.some(x => x.hardened)) return

  // test deriving path from master
  f.children.forEach((cf) => {
    let chd = hd.derivePath(cf.path)
    verify(chd, prv, cf, network)

    let chdNoM = hd.derivePath(cf.path.slice(2)) // no m/
    verify(chdNoM, prv, cf, network)
  })

  // test deriving path from successive children
  let shd = hd
  f.children.forEach((cf) => {
    if (cf.m === undefined) return
    if (cf.hardened) {
      shd = shd.deriveHardened(cf.m)
    } else {
      // verify any publicly derived children
      if (cf.base58) verify(shd.neutered().derive(cf.m), false, cf, network)

      shd = shd.derive(cf.m)
      verify(shd, prv, cf, network)
    }

    expect(() => {
      shd.derivePath('m/0')
    }).toThrow(/Expected master, got child/)

    verify(shd, prv, cf, network)
  })
}

validAll.forEach((ff) => {
  it(ff.comment || ff.base58Priv, () => {
    let network
    if (ff.network === 'litecoin') network = LITECOIN

    let hd = BIP32.fromBase58(ff.base58Priv, network)
    verify(hd, true, ff, network)

    hd = BIP32.fromBase58(ff.base58, network)
    verify(hd, false, ff, network)

    if (ff.seed) {
      let seed = tools.fromHex(ff.seed)
      hd = BIP32.fromSeed(seed, network)
      verify(hd, true, ff, network)
    }
  })
})

it('invalid ecc library throws', () => {
  expect(() => {
    BIP32Creator({ isPoint: () => false })
  }).toThrow(/ecc library invalid/)
  // Run with no schnorr and check it doesn't throw
  BIP32Creator({ ...ecc, signSchnorr: null, verifySchnorr: null })
})

describe('fromBase58 throws', () => {
  invalid.fromBase58.forEach((f) => {
    it(f.exception, () => {
      expect(() => {
        let network
        if (f.network === 'litecoin') network = LITECOIN

        BIP32.fromBase58(f.string, network)
      }).toThrow(new RegExp(f.exception))
    })
  })
})

it('works for Private -> public (neutered)', () => {
  let f = valid[1]
  let c = f.master.children[0]

  let master = BIP32.fromBase58(f.master.base58Priv)
  let child = master.derive(c.m).neutered()

  expect(child.toBase58()).toBe(c.base58)
})

it('works for Private -> public (neutered, hardened)', () => {
  let f = valid[0]
  let c = f.master.children[0]

  let master = BIP32.fromBase58(f.master.base58Priv)
  let child = master.deriveHardened(c.m).neutered()

  expect(c.base58).toBe(child.toBase58())
})

it('works for Public -> public', () => {
  let f = valid[1]
  let c = f.master.children[0]

  let master = BIP32.fromBase58(f.master.base58)
  let child = master.derive(c.m)

  expect(c.base58).toBe(child.toBase58())

  const hdNeutered = BIP32.fromPublicKey(tools.fromHex(f.master.pubKey), tools.fromHex(f.master.chainCode))
  expect(child.toBase58()).toBe(hdNeutered.derive(c.m).toBase58())
})

it('throws on Public -> public (hardened)', () => {
  let f = valid[0]
  let c = f.master.children[0]

  let master = BIP32.fromBase58(f.master.base58)

  expect(() => {
    master.deriveHardened(c.m)
  }).toThrow(/Missing private key for hardened child key/)
})

describe('throws on wrong types', () => {
  let f = valid[0]
  let master = BIP32.fromBase58(f.master.base58)

  invalid.derive.forEach((fx) => {
    it(`derive(${fx.index})`, () => {
      expect(() => {
        master.derive(fx.index)
      }).toThrow('Expected UInt32')
    })
  })

  invalid.deriveHardened.forEach((fx) => {
    it(`deriveHardened(${fx.index})`, () => {
      expect(() => {
        master.deriveHardened(fx.index)
      }).toThrow('Expected UInt31')
    })
  })

  invalid.derivePath.forEach((fx) => {
    it(`derivePath(${fx.derivationPath})`, () => {
      expect(() => {
        master.derivePath(fx.derivationPath)
      }).toThrow(fx.exception)
    })
  })

  it('fromPrivateKey with invalid length', () => {
    let ONES = new Uint8Array(32).fill(1)

    expect(() => {
      BIP32.fromPrivateKey(new Uint8Array(2), ONES)
    }).toThrow('Expected Uint8Array of length 32')
  })

  it('fromPrivateKey with zero key', () => {
    let ZERO = new Uint8Array(32)
    let ONES = new Uint8Array(32).fill(1)

    expect(() => {
      BIP32.fromPrivateKey(ZERO, ONES)
    }).toThrow(/Private key not in range \[1, n\)/)
  })
})

it('works when private key has leading zeros', () => {
  let key = 'xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr'
  let hdkey = BIP32.fromBase58(key)

  expect(tools.toHex(hdkey.privateKey)).toBe('00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd')
  let child = hdkey.derivePath('m/44\'/0\'/0\'/0/0\'')
  expect(tools.toHex(child.privateKey)).toBe('3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb')
})

describe('fromSeed', () => {
  invalid.fromSeed.forEach((f) => {
    it(f.exception, () => {
      expect(() => {
        BIP32.fromSeed(tools.fromHex(f.seed))
      }).toThrow(new RegExp(f.exception))
    })
  })
})

it('ecdsa', () => {
  let seed = new Uint8Array(32).fill(1)
  let hash = new Uint8Array(32).fill(2)
  let signature = tools.fromHex('9636ee2fac31b795a308856b821ebe297dda7b28220fb46ea1fbbd7285977cc04c82b734956246a0f15a9698f03f546d8d96fe006c8e7bd2256ca7c8229e6f5c')
  let schnorrsig = tools.fromHex('17179c75363d03a9948b2738bbbf91c1eaf257bb6ef72c440419dee16e2777b74bb4fe5387579cb868fa1ace009b1f3db3f0ba7449aa3bd7a64d2868a2f603f1')
  let signatureLowR = tools.fromHex('0587a40b391b76596c257bf59565b24eaff2cc42b45caa2640902e73fb97a6e702c3402ab89348a7dae1bf171c3e172fa60353d7b01621a94cb7caca59b995db')
  let node = BIP32.fromSeed(seed)

  expect(tools.toHex(node.sign(hash))).toBe(tools.toHex(signature))
  expect(tools.toHex(node.sign(hash, true))).toBe(tools.toHex(signatureLowR))
  expect(tools.toHex(node.signSchnorr(hash))).toBe(tools.toHex(schnorrsig))
  expect(node.verify(hash, signature)).toBe(true)
  expect(node.verify(seed, signature)).toBe(false)
  expect(node.verify(hash, signatureLowR)).toBe(true)
  expect(node.verify(seed, signatureLowR)).toBe(false)
  expect(node.verifySchnorr(hash, schnorrsig)).toBe(true)
  expect(node.verifySchnorr(seed, schnorrsig)).toBe(false)

  const neuteredNode = node.neutered()
  expect(() => neuteredNode.sign(hash)).toThrow(/Missing private key/)
  expect(() => neuteredNode.signSchnorr(hash)).toThrow(/Missing private key/)
})

it('ecdsa - no schnorr', () => {
  let seed = new Uint8Array(32).fill(1)
  let hash = new Uint8Array(32).fill(2)
  const tweak = new Uint8Array(32).fill(3)

  const bip32NoSchnorr = BIP32Creator({ ...ecc, signSchnorr: null, verifySchnorr: null })
  const node = bip32NoSchnorr.fromSeed(seed)

  expect(() => node.signSchnorr(hash)).toThrow(/signSchnorr not supported by ecc library/)
  expect(() => node.verifySchnorr(hash)).toThrow(/verifySchnorr not supported by ecc library/)

  const tweakedNode = node.tweak(tweak)
  expect(() => tweakedNode.signSchnorr(hash)).toThrow(/signSchnorr not supported by ecc library/)
  expect(() => tweakedNode.verifySchnorr(hash)).toThrow(/verifySchnorr not supported by ecc library/)

  const signer = node.neutered().tweak(tweak)
  expect(() => signer.verifySchnorr(hash)).toThrow(/verifySchnorr not supported by ecc library/)
})

it('ecc without tweak support', () => {
  let seed = new Uint8Array(32).fill(1)
  const tweak = new Uint8Array(32).fill(3)

  const bip32NoTweak = BIP32Creator({ ...ecc, xOnlyPointAddTweak: null, privateNegate: null })
  const node = bip32NoTweak.fromSeed(seed)
  const nodeWithoutPrivKey = bip32NoTweak.fromPublicKey(node.publicKey, node.chainCode)

  expect(() => node.tweak(tweak)).toThrow(/privateNegate not supported by ecc library/)
  expect(() => nodeWithoutPrivKey.tweak(tweak)).toThrow(/xOnlyPointAddTweak not supported by ecc library/)
})

it('tweak', () => {
  const seed = new Uint8Array(32).fill(1)
  const hash = new Uint8Array(32).fill(2)
  const tweak = new Uint8Array(32).fill(3)
  const signature = tools.fromHex('5a38c6652feb5166c9c91cfa5fa4a4c7cec27445d4619499df8afdd05ebc823246d644b0c7d3b960625393df537f900528ec4b14e6ddab8fd0c7e87c98cfe9d0')
  const schnorrsig = tools.fromHex('f9d65ae90d7f6774a8c51e52147ceb664741755d1cab4a5c5f529a6a8b6a7d71e9a49ad008bef95b2185b60126f654e2382c5eaa71a76ddd08eb397c90658484')
  const signatureLowR = tools.fromHex('5a38c6652feb5166c9c91cfa5fa4a4c7cec27445d4619499df8afdd05ebc823246d644b0c7d3b960625393df537f900528ec4b14e6ddab8fd0c7e87c98cfe9d0')
  const signer = BIP32.fromSeed(seed).tweak(tweak)

  expect(tools.toHex(signer.sign(hash))).toBe(tools.toHex(signature))
  expect(tools.toHex(signer.sign(hash, true))).toBe(tools.toHex(signatureLowR))
  expect(tools.toHex(signer.signSchnorr(hash))).toBe(tools.toHex(schnorrsig))
  expect(signer.verify(hash, signature)).toBe(true)
  expect(signer.verify(seed, signature)).toBe(false)
  expect(signer.verify(hash, signatureLowR)).toBe(true)
  expect(signer.verify(seed, signatureLowR)).toBe(false)
  expect(signer.verifySchnorr(hash, schnorrsig)).toBe(true)
  expect(signer.verifySchnorr(seed, schnorrsig)).toBe(false)
})

it('tweak - neutered', () => {
  const seed = new Uint8Array(32).fill(1)
  const hash = new Uint8Array(32).fill(2)
  const tweak = new Uint8Array(32).fill(3)
  const signature = tools.fromHex('5a38c6652feb5166c9c91cfa5fa4a4c7cec27445d4619499df8afdd05ebc823246d644b0c7d3b960625393df537f900528ec4b14e6ddab8fd0c7e87c98cfe9d0')
  const schnorrsig = tools.fromHex('f9d65ae90d7f6774a8c51e52147ceb664741755d1cab4a5c5f529a6a8b6a7d71e9a49ad008bef95b2185b60126f654e2382c5eaa71a76ddd08eb397c90658484')
  const signatureLowR = tools.fromHex('5a38c6652feb5166c9c91cfa5fa4a4c7cec27445d4619499df8afdd05ebc823246d644b0c7d3b960625393df537f900528ec4b14e6ddab8fd0c7e87c98cfe9d0')
  const signer = BIP32.fromSeed(seed).neutered().tweak(tweak)

  expect(() => signer.sign(hash)).toThrow(/Missing private key/)
  expect(() => signer.signSchnorr(hash)).toThrow(/Missing private key/)

  expect(signer.verify(hash, signature)).toBe(true)
  expect(signer.verify(seed, signature)).toBe(false)
  expect(signer.verify(hash, signatureLowR)).toBe(true)
  expect(signer.verify(seed, signatureLowR)).toBe(false)
  expect(signer.verifySchnorr(hash, schnorrsig)).toBe(true)
  expect(signer.verifySchnorr(seed, schnorrsig)).toBe(false)
})

it('xOnlyPublicKey returns 32-byte x-only key', () => {
  const seed = new Uint8Array(32).fill(1)
  const node = BIP32.fromSeed(seed)
  expect(node.xOnlyPublicKey.length).toBe(32)
  // x-only key should be publicKey bytes 1..33
  expect(tools.toHex(node.xOnlyPublicKey)).toBe(tools.toHex(node.publicKey.slice(1, 33)))
})

it('capabilities and hasCapability', () => {
  const seed = new Uint8Array(32).fill(1)
  const node = BIP32.fromSeed(seed)

  // Private node has signing capabilities
  expect(node.hasCapability(1)).toBe(true)   // Some capability bit
  expect(node.capabilities).toBeGreaterThan(0)

  // Neutered node loses sign capabilities
  const neutered = node.neutered()
  expect(neutered.capabilities).toBeGreaterThan(0) // Still has verify
  expect(neutered.privateKey).toBe(undefined)
})

it('capabilities without schnorr', () => {
  const bip32NoSchnorr = BIP32Creator({ ...ecc, signSchnorr: null, verifySchnorr: null })
  const seed = new Uint8Array(32).fill(1)
  const node = bip32NoSchnorr.fromSeed(seed)
  // Should still have ECDSA capabilities
  expect(node.capabilities).toBeGreaterThan(0)

  const neutered = node.neutered()
  expect(neutered.capabilities).toBeGreaterThan(0)
})

it('fromSeed throws on non-Uint8Array', () => {
  expect(() => BIP32.fromSeed('not a buffer')).toThrow('Expected Uint8Array')
  expect(() => BIP32.fromSeed(123)).toThrow('Expected Uint8Array')
})

it('fromPrecomputed creates key without validation', () => {
  const seed = new Uint8Array(32).fill(1)
  const master = BIP32.fromSeed(seed)
  const child = master.derivePath("m/44'/0'/0'")

  const restored = BIP32.fromPrecomputed(
    child.privateKey,
    child.publicKey,
    child.chainCode,
    child.depth,
    child.index,
    child.parentFingerprint
  )

  expect(tools.toHex(restored.publicKey)).toBe(tools.toHex(child.publicKey))
  expect(tools.toHex(restored.privateKey)).toBe(tools.toHex(child.privateKey))
  expect(restored.depth).toBe(child.depth)
  expect(restored.index).toBe(child.index)
  expect(restored.parentFingerprint).toBe(child.parentFingerprint)
  expect(restored.toBase58()).toBe(child.toBase58())
})

it('fromPrecomputed with neutered key', () => {
  const seed = new Uint8Array(32).fill(1)
  const master = BIP32.fromSeed(seed)

  const restored = BIP32.fromPrecomputed(
    undefined,
    master.publicKey,
    master.chainCode,
    0,
    0,
    0
  )

  expect(restored.isNeutered()).toBe(true)
  expect(tools.toHex(restored.publicKey)).toBe(tools.toHex(master.publicKey))
})

it('derive skips when IL is not a valid private key', () => {
  // Mock isPrivate so it passes testEcc and fromSeed, then rejects the first derive IL
  let armed = false
  let skipCount = 0
  const mockEcc = {
    ...ecc,
    isPrivate: (d) => {
      if (armed && skipCount === 0) {
        skipCount++
        return false // First call after arming fails, triggers skip to index+1
      }
      return ecc.isPrivate(d)
    }
  }
  const bip32Mock = BIP32Creator(mockEcc)
  const seed = new Uint8Array(32).fill(1)
  const master = bip32Mock.fromSeed(seed)
  armed = true // Arm AFTER fromSeed so seed validation passes
  const child = master.derive(0)
  expect(child).toBeDefined()
  expect(skipCount).toBe(1) // Confirms the skip path was hit
})

it('derive skips when privateAdd returns null', () => {
  // Mock privateAdd so it passes testEcc, then returns null on first derivation call
  let armed = false
  let skipCount = 0
  const mockEcc = {
    ...ecc,
    privateAdd: (d, tweak) => {
      if (armed && skipCount === 0) {
        skipCount++
        return null // First derivation triggers skip to index+1
      }
      return ecc.privateAdd(d, tweak)
    }
  }
  const bip32Mock = BIP32Creator(mockEcc)
  armed = true
  const seed = new Uint8Array(32).fill(1)
  const master = bip32Mock.fromSeed(seed)
  const child = master.derive(0)
  expect(child).toBeDefined()
  expect(child.depth).toBe(1)
  expect(skipCount).toBe(1)
})

it('derive skips when pointAddScalar returns null (public derivation)', () => {
  // Mock pointAddScalar so it passes testEcc, then returns null on first derivation call
  let armed = false
  let skipCount = 0
  const mockEcc = {
    ...ecc,
    pointAddScalar: (p, tweak, compressed) => {
      if (armed && skipCount === 0) {
        skipCount++
        return null // First derivation triggers skip to index+1
      }
      return ecc.pointAddScalar(p, tweak, compressed)
    }
  }
  const bip32Mock = BIP32Creator(mockEcc)
  armed = true
  const seed = new Uint8Array(32).fill(1)
  const master = bip32Mock.fromSeed(seed)
  const neutered = master.neutered()
  const child = neutered.derive(0)
  expect(child).toBeDefined()
  expect(child.depth).toBe(1)
  expect(skipCount).toBe(1)
})
