// SPDX-License-Identifier: AGPL-3.0-or-later
// What the relay needs from crypto: sha256 for ids, base64url, Ed25519 verification of hellos
// and of the signed GET on /v1/frames (WebCrypto only, no dependencies at runtime).

const te = new TextEncoder();

export function b64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64urlEncode(b: Uint8Array): string {
  let bin = "";
  for (const x of b) bin += String.fromCharCode(x);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function hex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? te.encode(data) : data;
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

/** deviceId / supervisorId of a raw Ed25519 public key: hex(sha256(raw)). */
export async function idOfKey(rawKeyB64url: string): Promise<string | null> {
  let raw: Uint8Array;
  try {
    raw = b64urlDecode(rawKeyB64url);
  } catch {
    return null;
  }
  if (raw.length !== 32) return null;
  return sha256Hex(raw);
}

/** Ed25519 signature (b64url, 64 bytes) over the UTF-8 bytes of msg, with a raw 32-byte key (b64url). */
export async function verifyEd25519(rawKeyB64url: string, msg: string, sigB64url: string): Promise<boolean> {
  try {
    const raw = b64urlDecode(rawKeyB64url);
    const sig = b64urlDecode(sigB64url);
    if (raw.length !== 32 || sig.length !== 64) return false;
    const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, te.encode(msg));
  } catch {
    return false;
  }
}

export function randomHex(bytes: number): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return hex(b);
}

export function randomB64url(bytes: number): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return b64urlEncode(b);
}
