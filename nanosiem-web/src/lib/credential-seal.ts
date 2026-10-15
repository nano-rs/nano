// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Browser half of the sealed ingest-credential envelope (NAN-2593).
 *
 * The hosted-shared "Add data" flow never lets the SIEM API or the control
 * plane see an ingest token. The browser makes an ephemeral key pair, sends
 * only the public key with the issuance request, and the platform seals the token
 * it mints to that key (NAN-2591). The browser opens it here, shows it once,
 * and drops the private key.
 *
 * Canonical format (ONBOARDING-CONTRACTS.md "CANONICAL sealed-token format";
 * reference opener: the platform `packages/shared/src/crypto/ingest-credential-envelope.ts`):
 *
 *   sealed_token = base64url(utf8(JSON {"v":1,"alg","epk","salt","iv","ct"}))
 *   alg  = "X25519-HKDF-SHA256-A256GCM" | "P256-HKDF-SHA256-A256GCM"
 *   Z    = ECDH(browser private key, epk)          X25519 output / P-256 X coordinate
 *   info = utf8("nano.ingest-credential.seal.v1") ‖ 0x00 ‖ utf8(alg) ‖ 0x00 ‖ epk ‖ reveal_public_key
 *   K    = HKDF-SHA256(Z, salt, info, 32)
 *   token = AES-256-GCM-decrypt(K, iv, ct‖tag, AAD = utf8(request_id ‖ tenant_id))
 *
 * Every binary field is unpadded base64url. The private key is generated
 * non-extractable and lives only in memory (a component ref); nothing here
 * touches storage.
 */

export const ENVELOPE_VERSION = 1 as const;
export const ENVELOPE_ALG_X25519 = 'X25519-HKDF-SHA256-A256GCM' as const;
export const ENVELOPE_ALG_P256 = 'P256-HKDF-SHA256-A256GCM' as const;
export type EnvelopeAlg = typeof ENVELOPE_ALG_X25519 | typeof ENVELOPE_ALG_P256;
export const ENVELOPE_HKDF_LABEL = 'nano.ingest-credential.seal.v1';
export const ENVELOPE_SALT_BYTES = 32;
export const ENVELOPE_IV_BYTES = 12;
export const ENVELOPE_TAG_BYTES = 16;
export const MAX_SEALED_TOKEN_CHARS = 4096;

/** The `reveal_key_alg` the SIEM API takes. */
export type RevealKeyAlg = 'x25519' | 'p256';

export interface IngestCredentialEnvelope {
  v: typeof ENVELOPE_VERSION;
  alg: EnvelopeAlg;
  epk: string;
  salt: string;
  iv: string;
  ct: string;
}

export class SealedTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SealedTokenError';
  }
}

// ---------------------------------------------------------------- encodings

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

/** Unpadded base64url (RFC 4648 §5). */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63] + B64URL[n & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = bytes[i] << 16;
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63];
  } else if (rest === 2) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64URL[(n >> 18) & 63] + B64URL[(n >> 12) & 63] + B64URL[(n >> 6) & 63];
  }
  return out;
}

/** Strict unpadded base64url: refuses padding, other alphabets and non-canonical trailing bits. */
export function base64urlDecode(text: string): Uint8Array {
  if (!B64URL_RE.test(text) || text.length % 4 === 1) throw new SealedTokenError('invalid base64url');
  const out = new Uint8Array(Math.floor((text.length * 3) / 4));
  let bits = 0;
  let value = 0;
  let o = 0;
  for (const ch of text) {
    value = ((value << 6) | B64URL.indexOf(ch)) & 0xffffff;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (value >> bits) & 0xff;
    }
  }
  if ((value & ((1 << bits) - 1)) !== 0) throw new SealedTokenError('invalid base64url');
  return out;
}

const encoder = new TextEncoder();

/** ASCII-only decode: tokens and the envelope JSON are ASCII by contract. */
function asciiDecode(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    if (b > 0x7e || (b < 0x20 && b !== 0x0a)) throw new SealedTokenError('non-ASCII envelope content');
    out += String.fromCharCode(b);
  }
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

/** WebCrypto wants a BufferSource backed by an ArrayBuffer (TS 5.7+ typing). */
function buf(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

// ------------------------------------------------------------ contract helpers

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** AAD = utf8(request_id ‖ tenant_id); both lowercase canonical UUIDs (72 bytes). */
export function envelopeAad(requestId: string, tenantId: string): Uint8Array {
  const r = requestId.toLowerCase();
  const t = tenantId.toLowerCase();
  if (!UUID_RE.test(r) || !UUID_RE.test(t)) throw new SealedTokenError('envelope AAD needs canonical UUIDs');
  return encoder.encode(r + t);
}

/** HKDF info = label ‖ 0x00 ‖ alg ‖ 0x00 ‖ epk ‖ recipient public key. */
export function envelopeHkdfInfo(alg: EnvelopeAlg, epk: Uint8Array, recipientPublicKey: Uint8Array): Uint8Array {
  return concat(
    encoder.encode(ENVELOPE_HKDF_LABEL),
    new Uint8Array([0]),
    encoder.encode(alg),
    new Uint8Array([0]),
    epk,
    recipientPublicKey,
  );
}

/** 32 raw bytes = X25519; a 65-byte 0x04-prefixed point = P-256. */
export function envelopeAlgForPublicKey(raw: Uint8Array): EnvelopeAlg {
  if (raw.length === 32) return ENVELOPE_ALG_X25519;
  if (raw.length === 65 && raw[0] === 0x04) return ENVELOPE_ALG_P256;
  throw new SealedTokenError('public key must be 32-byte X25519 or 65-byte uncompressed P-256');
}

/** Parse and shape-check a wire `sealed_token`; never returns partially valid input. */
export function decodeEnvelope(sealed: string): IngestCredentialEnvelope {
  if (typeof sealed !== 'string' || sealed.length === 0 || sealed.length > MAX_SEALED_TOKEN_CHARS) {
    throw new SealedTokenError('sealed token has an invalid length');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(asciiDecode(base64urlDecode(sealed)));
  } catch {
    throw new SealedTokenError('sealed token is not an envelope');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new SealedTokenError('sealed token is not an envelope');
  const e = parsed as Record<string, unknown>;
  if (Object.keys(e).sort().join(',') !== 'alg,ct,epk,iv,salt,v') throw new SealedTokenError('sealed token has unexpected fields');
  if (e.v !== ENVELOPE_VERSION) throw new SealedTokenError('unsupported envelope version');
  if (e.alg !== ENVELOPE_ALG_X25519 && e.alg !== ENVELOPE_ALG_P256) throw new SealedTokenError('unsupported envelope algorithm');
  for (const field of ['epk', 'salt', 'iv', 'ct'] as const) {
    if (typeof e[field] !== 'string') throw new SealedTokenError(`envelope ${field} must be base64url`);
  }
  const envelope = e as unknown as IngestCredentialEnvelope;
  if (envelopeAlgForPublicKey(base64urlDecode(envelope.epk)) !== envelope.alg) {
    throw new SealedTokenError('envelope epk does not match its algorithm');
  }
  if (base64urlDecode(envelope.salt).length !== ENVELOPE_SALT_BYTES) throw new SealedTokenError('envelope salt must be 32 bytes');
  if (base64urlDecode(envelope.iv).length !== ENVELOPE_IV_BYTES) throw new SealedTokenError('envelope iv must be 12 bytes');
  if (base64urlDecode(envelope.ct).length <= ENVELOPE_TAG_BYTES) throw new SealedTokenError('envelope ciphertext is too short');
  return envelope;
}

// ------------------------------------------------------------------ WebCrypto

function defaultSubtle(): SubtleCrypto {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new SealedTokenError('WebCrypto is unavailable (a secure https context is required)');
  return subtle;
}

/** An ephemeral reveal key pair. Hold it in memory only (a ref), never in storage or a query cache. */
export interface RevealKeyPair {
  alg: RevealKeyAlg;
  envelopeAlg: EnvelopeAlg;
  /** Non-extractable private key. */
  privateKey: CryptoKey;
  /** Raw public key bytes (32-byte X25519 or 65-byte uncompressed P-256). */
  publicKey: Uint8Array;
  /** `reveal_public_key` for the request: unpadded base64url of `publicKey`. */
  publicKeyB64u: string;
}

/**
 * Generate the reveal key pair: X25519 where the browser supports it, else
 * P-256 ECDH (older Safari / Chromium). The private key is non-extractable.
 */
export async function generateRevealKeyPair(subtle: SubtleCrypto = defaultSubtle()): Promise<RevealKeyPair> {
  let pair: CryptoKeyPair;
  let alg: RevealKeyAlg;
  try {
    pair = (await subtle.generateKey({ name: 'X25519' }, false, ['deriveBits'])) as CryptoKeyPair;
    alg = 'x25519';
  } catch {
    pair = (await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits'])) as CryptoKeyPair;
    alg = 'p256';
  }
  const publicKey = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  return {
    alg,
    envelopeAlg: alg === 'x25519' ? ENVELOPE_ALG_X25519 : ENVELOPE_ALG_P256,
    privateKey: pair.privateKey,
    publicKey,
    publicKeyB64u: base64urlEncode(publicKey),
  };
}

/**
 * Open a `sealed_token` with the key pair that requested it. Throws (and
 * reveals nothing) if the envelope is malformed, sealed to another key,
 * tampered with, or bound to another request or tenant.
 */
export async function openSealedToken(args: {
  sealed: string;
  keyPair: Pick<RevealKeyPair, 'privateKey' | 'publicKey'>;
  requestId: string;
  tenantId: string;
  subtle?: SubtleCrypto;
}): Promise<string> {
  const subtle = args.subtle ?? defaultSubtle();
  const envelope = decodeEnvelope(args.sealed);
  if (envelopeAlgForPublicKey(args.keyPair.publicKey) !== envelope.alg) {
    throw new SealedTokenError('envelope algorithm does not match the reveal key');
  }
  const aad = envelopeAad(args.requestId, args.tenantId);
  const epk = base64urlDecode(envelope.epk);
  const ecdh = envelope.alg === ENVELOPE_ALG_X25519 ? { name: 'X25519' } : { name: 'ECDH', namedCurve: 'P-256' };
  let shared: Uint8Array;
  try {
    const peer = await subtle.importKey('raw', buf(epk), ecdh, false, []);
    shared = new Uint8Array(
      await subtle.deriveBits({ name: ecdh.name, public: peer } as EcdhKeyDeriveParams, args.keyPair.privateKey, 256),
    );
  } catch {
    throw new SealedTokenError('key agreement failed');
  }
  try {
    if (shared.every((b) => b === 0)) throw new SealedTokenError('key agreement produced a degenerate secret');
    const ikm = await subtle.importKey('raw', buf(shared), 'HKDF', false, ['deriveKey']);
    const key = await subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: buf(base64urlDecode(envelope.salt)),
        info: buf(envelopeHkdfInfo(envelope.alg, epk, args.keyPair.publicKey)),
      },
      ikm,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    let plaintext: Uint8Array;
    try {
      plaintext = new Uint8Array(
        await subtle.decrypt(
          { name: 'AES-GCM', iv: buf(base64urlDecode(envelope.iv)), additionalData: buf(aad), tagLength: 128 },
          key,
          buf(base64urlDecode(envelope.ct)),
        ),
      );
    } catch {
      throw new SealedTokenError('the sealed token did not open with this browser key (wrong key, request or tenant, or tampered)');
    }
    try {
      return asciiDecode(plaintext);
    } finally {
      plaintext.fill(0);
    }
  } finally {
    shared.fill(0);
  }
}
