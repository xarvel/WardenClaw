// SPDX-License-Identifier: Apache-2.0
// Ed25519 via node:crypto. Device public key stored in the gateway is
// base64url raw 32 bytes (same as what the client sends in connect.device.publicKey).
import { createPublicKey, createPrivateKey, generateKeyPairSync, sign, verify, timingSafeEqual, createHash } from "node:crypto";

// Same 14 encodings as daemon/envelope/ticket.go ed25519SmallOrder: the eight points of
// order dividing 8, plus the non-canonical encodings crypto/ed25519 still verifies.
const SMALL_ORDER_ED25519 = new Set([
  "0100000000000000000000000000000000000000000000000000000000000000",
  "0100000000000000000000000000000000000000000000000000000000000080",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000080",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
  "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
  "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
  "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
]);

/** @param {Buffer | Uint8Array} raw */
function isSmallOrderEd25519(raw) {
  return raw.length === 32 && SMALL_ORDER_ED25519.has(Buffer.from(raw).toString("hex"));
}

/** @param {string} s */
export function b64urlToBuffer(s) {
  const norm = s.replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(norm, "base64");
}

/** @param {Buffer | Uint8Array} b */
export function bufferToB64url(b) {
  return Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * @param {string} publicKeyB64url raw 32-byte Ed25519 public key, base64url (padding is allowed)
 */
export function publicKeyFromB64url(publicKeyB64url) {
  const raw = b64urlToBuffer(publicKeyB64url.trim());
  if (raw.length !== 32) throw new Error(`Ed25519 public key must be 32 bytes, got ${raw.length}`);
  if (isSmallOrderEd25519(raw)) throw new Error("Ed25519 public key has small order");
  return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: bufferToB64url(raw) }, format: "jwk" });
}

/**
 * deviceId of a key, as computed during pairing (OpenClaw, app, wardend): hex(sha256(raw 32 bytes)).
 * Returns null if the key cannot be parsed.
 * @param {unknown} publicKeyB64url
 * @returns {string | null}
 */
export function deviceIdOfPublicKey(publicKeyB64url) {
  if (typeof publicKeyB64url !== "string" || !publicKeyB64url.trim()) return null;
  const raw = b64urlToBuffer(publicKeyB64url.trim());
  if (raw.length !== 32 || isSmallOrderEd25519(raw)) return null;
  return createHash("sha256").update(raw).digest("hex");
}

/**
 * A key is only valid for a device if deviceId = sha256(key): a foreign key under a trusted id
 * (gateway DB may write an agent uid) would otherwise sign decisions on behalf of the phone.
 * @param {unknown} publicKeyB64url
 * @param {string} deviceId
 */
export function publicKeyMatchesDeviceId(publicKeyB64url, deviceId) {
  const id = deviceIdOfPublicKey(publicKeyB64url);
  return id !== null && id === String(deviceId).toLowerCase();
}

/**
 * @param {string} message
 * @param {string} signatureB64url
 * @param {string} publicKeyB64url
 * @returns {boolean}
 */
export function verifyEd25519(message, signatureB64url, publicKeyB64url) {
  try {
    const key = publicKeyFromB64url(publicKeyB64url);
    const sig = b64urlToBuffer(signatureB64url.trim());
    if (sig.length !== 64) return false;
    return verify(null, Buffer.from(message, "utf8"), key, sig);
  } catch {
    return false;
  }
}

/** Plugin journal key: generation and JWK (de)serialisation. */
export function generateJournalKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: /** @type {string} */ (publicKey.export({ format: "jwk" }).x),
    privateJwk: privateKey.export({ format: "jwk" }),
  };
}

/**
 * @param {import("node:crypto").JsonWebKey} privateJwk
 * @param {string} message
 */
export function signWithJwk(privateJwk, message) {
  const key = createPrivateKey({ key: privateJwk, format: "jwk" });
  return bufferToB64url(sign(null, Buffer.from(message, "utf8"), key));
}

/** Constant-time secret comparison (via sha256, to prevent length side-channel). */
export function secretEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const ha = createHash("sha256").update(a, "utf8").digest();
  const hb = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(ha, hb);
}
