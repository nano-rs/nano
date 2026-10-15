// SPDX-License-Identifier: AGPL-3.0-or-later
/**
 * Test-only sealer for ingest-credential envelopes (NAN-2593): an independent
 * node:crypto implementation of the canonical format the platform's fulfilment
 * worker produces (ONBOARDING-CONTRACTS.md, "CANONICAL sealed-token format").
 * Never imported by application code.
 */
import { createCipheriv, createECDH, createPrivateKey, createPublicKey, diffieHellman, hkdfSync, randomBytes, type KeyObject } from 'node:crypto';
import {
  ENVELOPE_ALG_P256,
  ENVELOPE_ALG_X25519,
  base64urlDecode,
  base64urlEncode,
  envelopeAad,
  envelopeHkdfInfo,
  type EnvelopeAlg,
  type RevealKeyAlg,
} from './credential-seal';

export const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

export interface NodeKey { privateKey: KeyObject; raw: Uint8Array }

export function nodeKeyFromScalar(alg: RevealKeyAlg, scalarHex: string): NodeKey {
  const scalar = Buffer.from(scalarHex, 'hex');
  if (alg === 'x25519') {
    const privateKey = createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, scalar]), format: 'der', type: 'pkcs8' });
    return { privateKey, raw: new Uint8Array(Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x!, 'base64url')) };
  }
  const ecdh = createECDH('prime256v1');
  ecdh.setPrivateKey(scalar);
  const raw = ecdh.getPublicKey(null, 'uncompressed');
  const privateKey = createPrivateKey({
    key: { kty: 'EC', crv: 'P-256', d: scalar.toString('base64url'), x: raw.subarray(1, 33).toString('base64url'), y: raw.subarray(33, 65).toString('base64url') },
    format: 'jwk',
  });
  return { privateKey, raw: new Uint8Array(raw) };
}

export function nodePublicKey(raw: Uint8Array): KeyObject {
  const b = Buffer.from(raw);
  return raw.length === 32
    ? createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b.toString('base64url') }, format: 'jwk' })
    : createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: b.subarray(1, 33).toString('base64url'), y: b.subarray(33, 65).toString('base64url') }, format: 'jwk' });
}

export function seal(args: {
  token: string;
  recipientPublic: Uint8Array;
  requestId: string;
  tenantId: string;
  ephemeral: NodeKey;
  salt?: Uint8Array;
  iv?: Uint8Array;
}): string {
  const alg: EnvelopeAlg = args.recipientPublic.length === 32 ? ENVELOPE_ALG_X25519 : ENVELOPE_ALG_P256;
  const salt = args.salt ?? randomBytes(32);
  const iv = args.iv ?? randomBytes(12);
  const z = diffieHellman({ privateKey: args.ephemeral.privateKey, publicKey: nodePublicKey(args.recipientPublic) });
  const key = Buffer.from(hkdfSync('sha256', z, salt, envelopeHkdfInfo(alg, args.ephemeral.raw, args.recipientPublic), 32));
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
  cipher.setAAD(envelopeAad(args.requestId, args.tenantId));
  const ct = Buffer.concat([cipher.update(Buffer.from(args.token, 'utf8')), cipher.final(), cipher.getAuthTag()]);
  const envelope = { v: 1, alg, epk: base64urlEncode(args.ephemeral.raw), salt: base64urlEncode(salt), iv: base64urlEncode(iv), ct: base64urlEncode(ct) };
  return base64urlEncode(new TextEncoder().encode(JSON.stringify(envelope)));
}

export function freshEphemeral(alg: RevealKeyAlg): NodeKey {
  return nodeKeyFromScalar(alg, alg === 'x25519' ? randomBytes(32).toString('hex') : randomP256Scalar());
}

export function randomP256Scalar(): string {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh.getPrivateKey('hex').padStart(64, '0');
}

/** Seal `token` to a browser's `reveal_public_key` (unpadded base64url), as the platform does. */
export function sealToRevealKey(revealPublicKey: string, token: string, requestId: string, tenantId: string): string {
  const raw = base64urlDecode(revealPublicKey);
  return seal({ token, recipientPublic: raw, requestId, tenantId, ephemeral: freshEphemeral(raw.length === 32 ? 'x25519' : 'p256') });
}
