// SPDX-License-Identifier: GPL-3.0-or-later
// Payload encryption of the relay transport (protocol/README.md section 11), no Expo/RN, tested in
// node against protocol/vectors/relay_vectors.json (the Go side: daemon/relaybox.go).
//
//   shared = X25519(my enc private, their enc public)
//   key    = HKDF-SHA256(ikm = shared, salt = sha256(supervisorId || deviceId), info = "wardenclaw.relay.v1")
//   body   = b64url(nonce(24) || XChaCha20-Poly1305(key, nonce, plaintext, aad))
//   aad    = canonicalJson({type:"wardenclaw.relay.aad.v1", id, from, to, kind, exp})
//
// A pair frame carries the device's X25519 public key in front of the box (section 6).
import { x25519 } from "@noble/curves/ed25519";
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { canonicalJson } from "./canonical";
import { b64url, utf8Encode } from "./bytes";

export const BOX_INFO = "wardenclaw.relay.v1";
export const AAD_TYPE = "wardenclaw.relay.aad.v1";
export const ENC_KEY_LEN = 32;
export const NONCE_LEN = 24;
const TAG_LEN = 16;

export type EncKeyPair = { privateKey: Uint8Array; publicKey: Uint8Array };

/** The device's X25519 key from 32 random bytes (the caller brings the randomness: expo-crypto in the app). */
export function encKeyPair(random32: Uint8Array): EncKeyPair {
  if (random32.length !== ENC_KEY_LEN) throw new Error("relay box: enc key must be 32 bytes");
  const privateKey = Uint8Array.from(random32);
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

/** The raw X25519 shared secret; throws on a low-order public key (all-zero output). */
export function boxShared(myPrivate: Uint8Array, theirPublic: Uint8Array): Uint8Array {
  if (myPrivate.length !== ENC_KEY_LEN || theirPublic.length !== ENC_KEY_LEN) throw new Error("relay box: enc key must be 32 bytes");
  return x25519.getSharedSecret(myPrivate, theirPublic);
}

export function boxSalt(supervisorId: string, deviceId: string): Uint8Array {
  return sha256(utf8Encode(supervisorId + deviceId));
}

/** One key per (supervisor, device), both directions. */
export function boxKey(myPrivate: Uint8Array, theirPublic: Uint8Array, supervisorId: string, deviceId: string): Uint8Array {
  return hkdf(sha256, boxShared(myPrivate, theirPublic), boxSalt(supervisorId, deviceId), utf8Encode(BOX_INFO), 32);
}

/** The routing members of a frame as the receiver sees them (`from` is set by the relay). */
export type AadFields = { id: string; from: string; to: string; kind: string; exp: number };

export function boxAad(f: AadFields): string {
  return canonicalJson({ type: AAD_TYPE, id: f.id, from: f.from, to: f.to, kind: f.kind, exp: f.exp });
}

/** body of a msg frame: b64url(nonce || ciphertext). nonce: 24 fresh random bytes. */
export function boxSeal(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array, aad: string): string {
  if (nonce.length !== NONCE_LEN) throw new Error("relay box: nonce must be 24 bytes");
  const ct = xchacha20poly1305(key, nonce, utf8Encode(aad)).encrypt(plaintext);
  const out = new Uint8Array(NONCE_LEN + ct.length);
  out.set(nonce, 0);
  out.set(ct, NONCE_LEN);
  return b64url.encode(out);
}

/** Opens a msg body; throws when it is malformed or does not authenticate under this key and aad. */
export function boxOpen(key: Uint8Array, body: string, aad: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(body)) throw new Error("relay box: body is not base64url");
  const raw = b64url.decode(body);
  if (raw.length < NONCE_LEN + TAG_LEN) throw new Error("relay box: body too short");
  return xchacha20poly1305(key, raw.subarray(0, NONCE_LEN), utf8Encode(aad)).decrypt(raw.subarray(NONCE_LEN));
}

/** body of a pair frame: b64url(devEncPub(32) || nonce(24) || ciphertext) from a sealed msg body. */
export function pairBody(devEncPublic: Uint8Array, sealedBody: string): string {
  if (devEncPublic.length !== ENC_KEY_LEN) throw new Error("relay box: enc key must be 32 bytes");
  const raw = b64url.decode(sealedBody);
  const out = new Uint8Array(ENC_KEY_LEN + raw.length);
  out.set(devEncPublic, 0);
  out.set(raw, ENC_KEY_LEN);
  return b64url.encode(out);
}

/** The reverse of pairBody (the supervisor's side; the tests play it). */
export function splitPairBody(body: string): { enc: Uint8Array; sealedBody: string } {
  if (!/^[A-Za-z0-9_-]+$/.test(body)) throw new Error("relay box: body is not base64url");
  const raw = b64url.decode(body);
  if (raw.length < ENC_KEY_LEN + NONCE_LEN + TAG_LEN) throw new Error("relay box: body too short");
  return { enc: raw.slice(0, ENC_KEY_LEN), sealedBody: b64url.encode(raw.subarray(ENC_KEY_LEN)) };
}
