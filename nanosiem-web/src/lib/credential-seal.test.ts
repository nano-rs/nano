// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * NAN-2593: the browser opener for sealed ingest credentials.
 *
 * The sealer below is an independent node:crypto implementation of the
 * canonical format (ONBOARDING-CONTRACTS.md, "CANONICAL sealed-token format"),
 * the same derivation the platform's fulfilment worker performs. The opener under
 * test is WebCrypto only, so a pass means the two agree on every byte: JSON
 * field order, HKDF info, AAD and the GCM tag.
 */
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  ENVELOPE_ALG_P256,
  ENVELOPE_ALG_X25519,
  base64urlDecode,
  base64urlEncode,
  decodeEnvelope,
  envelopeAad,
  generateRevealKeyPair,
  openSealedToken,
  type RevealKeyAlg,
} from './credential-seal';
import { X25519_PKCS8_PREFIX, freshEphemeral, nodeKeyFromScalar, seal } from './credential-seal.fixture';

const subtle = globalThis.crypto.subtle;
const REQUEST = '0f6f5a1e-7c2b-4d1a-8e3f-2a9b8c7d6e5f';
const OTHER_REQUEST = '1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d';
const TENANT = 'b464ceb9-28a6-4249-8e29-3489627ac5f6';
const OTHER_TENANT = 'c575dfca-39b7-435a-9f3a-459a738bd607';

/** Import a fixed recipient scalar into WebCrypto, the way the browser holds its key. */
async function webcryptoRecipient(alg: RevealKeyAlg, scalarHex: string): Promise<{ privateKey: CryptoKey; publicKey: Uint8Array }> {
  const node = nodeKeyFromScalar(alg, scalarHex);
  const scalar = Buffer.from(scalarHex, 'hex');
  const privateKey = alg === 'x25519'
    ? await subtle.importKey('pkcs8', Buffer.concat([X25519_PKCS8_PREFIX, scalar]), { name: 'X25519' }, false, ['deriveBits'])
    : await subtle.importKey('jwk', {
      kty: 'EC', crv: 'P-256', d: scalar.toString('base64url'),
      x: Buffer.from(node.raw.subarray(1, 33)).toString('base64url'), y: Buffer.from(node.raw.subarray(33, 65)).toString('base64url'),
    }, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  return { privateKey, publicKey: node.raw };
}

// Fixed inputs. Recipient keys are RFC 7748 §6.1 (Alice) and RFC 6979 A.2.5;
// token = base64url(bytes 0x00..0x1f), salt = 0x20..0x3f, iv = 0x00..0x0b.
const VECTOR_TOKEN = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const VECTOR_SALT = Uint8Array.from({ length: 32 }, (_, i) => 0x20 + i);
const VECTOR_IV = Uint8Array.from({ length: 12 }, (_, i) => i);
const VECTORS: Record<RevealKeyAlg, { recipient: string; ephemeral: string; sealed: string }> = {
  x25519: {
    recipient: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
    ephemeral: '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb',
    sealed: 'eyJ2IjoxLCJhbGciOiJYMjU1MTktSEtERi1TSEEyNTYtQTI1NkdDTSIsImVwayI6IjNwN2JmWHQ5d2JUVFcySEM3T1ExTnotRFE4aGJlR2ROcmZ4LUZHLUlLMDgiLCJzYWx0IjoiSUNFaUl5UWxKaWNvS1NvckxDMHVMekF4TWpNME5UWTNPRGs2T3p3OVBqOCIsIml2IjoiQUFFQ0F3UUZCZ2NJQ1FvTCIsImN0IjoiTW14RExGRTJIQWxINTIwYzNXZmlZTmlKUTh2UmQyaE1OUVhxaU1OeDdyRmNTcGJYaE5xTGNzemM2N2dibFFBbnpHc015ekxKLU1XbWNudyJ9',
  },
  p256: {
    recipient: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
    ephemeral: '0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813',
    sealed: 'eyJ2IjoxLCJhbGciOiJQMjU2LUhLREYtU0hBMjU2LUEyNTZHQ00iLCJlcGsiOiJCT0ptM2YzQkptamJNTlRLUG85M1NVTXNRV0JFOHRLNHdRdnoxQUVxN19xS3Y2aGtCS0xwXy1aOVI4V0g3M3FYcF9SV3VHTzAwQ3o4YVNpWE9yV3h5emsiLCJzYWx0IjoiSUNFaUl5UWxKaWNvS1NvckxDMHVMekF4TWpNME5UWTNPRGs2T3p3OVBqOCIsIml2IjoiQUFFQ0F3UUZCZ2NJQ1FvTCIsImN0IjoidHg5MGlHbjNGQ2VsdUZCVEpqODVNQmhrNXJEU2M2dVo4RHJPRFp3V1JNZVd4UGxqcUozalB6THpyODVQckpEcUdjdGx2bTIzS0lKdGlpbyJ9',
  },
};

describe('sealed ingest credential opener (NAN-2593)', () => {
  it.each(['x25519', 'p256'] as const)('%s pinned vector: the node sealer reproduces it and the WebCrypto opener opens it', async (alg) => {
    const v = VECTORS[alg];
    const recipient = await webcryptoRecipient(alg, v.recipient);
    const sealed = seal({
      token: VECTOR_TOKEN, recipientPublic: recipient.publicKey, requestId: REQUEST, tenantId: TENANT,
      ephemeral: nodeKeyFromScalar(alg, v.ephemeral), salt: VECTOR_SALT, iv: VECTOR_IV,
    });
    expect(sealed).toBe(v.sealed);
    expect(decodeEnvelope(v.sealed).alg).toBe(alg === 'x25519' ? ENVELOPE_ALG_X25519 : ENVELOPE_ALG_P256);
    await expect(openSealedToken({ sealed: v.sealed, keyPair: recipient, requestId: REQUEST, tenantId: TENANT, subtle }))
      .resolves.toBe(VECTOR_TOKEN);
  });

  it('generates a non-extractable X25519 key and round-trips a fresh token', async () => {
    const pair = await generateRevealKeyPair(subtle);
    expect(pair.alg).toBe('x25519');
    expect(pair.publicKey.length).toBe(32);
    expect(pair.privateKey.extractable).toBe(false);
    expect(pair.publicKeyB64u).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const token = randomBytes(32).toString('base64url');
    const sealed = seal({ token, recipientPublic: pair.publicKey, requestId: REQUEST, tenantId: TENANT, ephemeral: freshEphemeral('x25519') });
    await expect(openSealedToken({ sealed, keyPair: pair, requestId: REQUEST, tenantId: TENANT, subtle })).resolves.toBe(token);
  });

  it('falls back to P-256 where X25519 is unsupported', async () => {
    const p256Only = new Proxy(subtle, {
      get(target, prop) {
        if (prop === 'generateKey') {
          return (algorithm: AlgorithmIdentifier | EcKeyGenParams, extractable: boolean, usages: KeyUsage[]) =>
            (algorithm as { name: string }).name === 'X25519'
              ? Promise.reject(new DOMException('Unrecognized name', 'NotSupportedError'))
              : target.generateKey(algorithm as EcKeyGenParams, extractable, usages);
        }
        const value = Reflect.get(target, prop);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) as SubtleCrypto;
    const pair = await generateRevealKeyPair(p256Only);
    expect(pair.alg).toBe('p256');
    expect(pair.publicKey.length).toBe(65);
    expect(pair.publicKey[0]).toBe(0x04);
    expect(base64urlDecode(pair.publicKeyB64u)).toEqual(pair.publicKey);
    const token = randomBytes(24).toString('base64url');
    const sealed = seal({ token, recipientPublic: pair.publicKey, requestId: REQUEST, tenantId: TENANT, ephemeral: freshEphemeral('p256') });
    await expect(openSealedToken({ sealed, keyPair: pair, requestId: REQUEST, tenantId: TENANT, subtle: p256Only })).resolves.toBe(token);
  });

  it('refuses a token bound to another request or tenant, another key, or tampered bytes', async () => {
    const v = VECTORS.x25519;
    const recipient = await webcryptoRecipient('x25519', v.recipient);
    const open = (sealed: string, requestId = REQUEST, tenantId = TENANT, keyPair = recipient) =>
      openSealedToken({ sealed, keyPair, requestId, tenantId, subtle });
    await expect(open(v.sealed, OTHER_REQUEST)).rejects.toThrow(/did not open/);
    await expect(open(v.sealed, REQUEST, OTHER_TENANT)).rejects.toThrow(/did not open/);
    const stranger = await generateRevealKeyPair(subtle);
    await expect(open(v.sealed, REQUEST, TENANT, stranger)).rejects.toThrow(/did not open/);
    const env = decodeEnvelope(v.sealed);
    const ct = base64urlDecode(env.ct);
    ct[0] ^= 1;
    const tampered = base64urlEncode(new TextEncoder().encode(JSON.stringify({ ...env, ct: base64urlEncode(ct) })));
    await expect(open(tampered)).rejects.toThrow(/did not open/);
    // A P-256 envelope never opens with an X25519 key.
    await expect(open(VECTORS.p256.sealed)).rejects.toThrow(/does not match the reveal key/);
  });

  it('rejects malformed envelopes before touching the key', () => {
    const env = decodeEnvelope(VECTORS.x25519.sealed);
    const enc = (o: unknown) => base64urlEncode(new TextEncoder().encode(JSON.stringify(o)));
    expect(() => decodeEnvelope('')).toThrow(/length/);
    expect(() => decodeEnvelope('not base64url!')).toThrow(/not an envelope/);
    expect(() => decodeEnvelope(`${VECTORS.x25519.sealed}=`)).toThrow(/not an envelope/);
    expect(() => decodeEnvelope(enc({ ...env, v: 2 }))).toThrow(/version/);
    expect(() => decodeEnvelope(enc({ ...env, extra: 1 }))).toThrow(/unexpected fields/);
    expect(() => decodeEnvelope(enc({ ...env, alg: ENVELOPE_ALG_P256 }))).toThrow(/epk does not match/);
    expect(() => decodeEnvelope(enc({ ...env, iv: base64urlEncode(new Uint8Array(8)) }))).toThrow(/iv must be 12/);
    expect(() => decodeEnvelope(enc({ ...env, salt: base64urlEncode(new Uint8Array(16)) }))).toThrow(/salt must be 32/);
    expect(() => decodeEnvelope(enc({ ...env, ct: base64urlEncode(new Uint8Array(16)) }))).toThrow(/too short/);
  });

  it('base64url is unpadded and strict', () => {
    for (let n = 0; n < 40; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      const text = base64urlEncode(bytes);
      expect(text).toBe(Buffer.from(bytes).toString('base64url'));
      expect(base64urlDecode(text)).toEqual(bytes);
    }
    expect(() => base64urlDecode('AB==')).toThrow();
    expect(() => base64urlDecode('AB+/')).toThrow();
    expect(() => base64urlDecode('AR')).toThrow(); // non-canonical trailing bits
  });

  it('AAD is request_id ‖ tenant_id, lowercase, 72 bytes', () => {
    const aad = envelopeAad(REQUEST.toUpperCase(), TENANT);
    expect(aad.length).toBe(72);
    expect(new TextDecoder().decode(aad)).toBe(REQUEST + TENANT);
    expect(() => envelopeAad('nope', TENANT)).toThrow();
  });
});
