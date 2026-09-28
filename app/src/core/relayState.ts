// SPDX-License-Identifier: GPL-3.0-or-later
// What the relay transport keeps between launches (protocol/README.md sections 5.1, 5.5):
//   - the device's X25519 key, next to the Ed25519 identity and with its protection (secure.ts);
//   - per supervisor, the last acked seq (the `seq` of the next resume) and the ids of the last
//     frames handled (a frame whose ack was lost comes again and must not be delivered twice).
// The seq and the ids are not secret: they live in the plain key-value store. Storage and
// randomness are the caller's (SecureStore, AsyncStorage and expo-crypto in the app, fakes in the
// tests): this file runs in node.
import { b64url, bytesToHex, hexToBytes } from "./bytes";
import { ENC_KEY_LEN, encKeyPair } from "./relayBox";
import { ID_RE, MSG_ID_RE } from "./relayProto";

export type EncKeyRec = { privateKeyHex: string; publicKey: string; createdAt: string };

/** One entry of a secret store: SecureStore under SK.encKey in the app. */
export type SecretSlot = { get(): Promise<string | null>; set(value: string): Promise<void> };

/** The stored key, or null when the entry is not a key this code wrote (the public half must match). */
export function parseEncKey(raw: string | null): EncKeyRec | null {
  if (!raw) return null;
  try {
    const r = JSON.parse(raw) as EncKeyRec;
    if (typeof r.privateKeyHex !== "string" || !/^[0-9a-f]{64}$/.test(r.privateKeyHex) || typeof r.createdAt !== "string") return null;
    return b64url.encode(encKeyPair(hexToBytes(r.privateKeyHex)).publicKey) === r.publicKey ? r : null;
  } catch {
    return null;
  }
}

/**
 * The device's encryption key: read, or generated once and written. A write that fails throws
 * (iOS without a passcode): a key that is not stored must not be used for pairing. An entry
 * that does not parse is replaced: the supervisors paired with the lost key must be paired again.
 */
export async function loadOrCreateEncKey(slot: SecretSlot, random: (n: number) => Uint8Array, now: () => number = Date.now): Promise<EncKeyRec> {
  const existing = parseEncKey(await slot.get());
  if (existing) return existing;
  const pair = encKeyPair(random(ENC_KEY_LEN));
  const rec: EncKeyRec = { privateKeyHex: bytesToHex(pair.privateKey), publicKey: b64url.encode(pair.publicKey), createdAt: new Date(now()).toISOString() };
  await slot.set(JSON.stringify(rec));
  return rec;
}

export function encPrivate(rec: EncKeyRec): Uint8Array {
  return hexToBytes(rec.privateKeyHex);
}

/** AsyncStorage, or anything of its shape. */
export type KeyValue = { getItem(key: string): Promise<string | null>; setItem(key: string, value: string): Promise<void> };

export type RelayStateRec = { seq: number; seen: string[] };

/** Ids kept across launches: more than a resume can replay twice, small enough to rewrite on every frame. */
export const SEEN_KEPT = 64;

export const relayStateKey = (supervisorId: string) => `wc.relay.state.v1.${supervisorId}`;

const EMPTY: RelayStateRec = { seq: 0, seen: [] };

function parseState(raw: string | null): RelayStateRec {
  if (!raw) return { ...EMPTY };
  try {
    const r = JSON.parse(raw) as RelayStateRec;
    if (!Number.isSafeInteger(r.seq) || r.seq < 0 || !Array.isArray(r.seen)) return { ...EMPTY };
    return { seq: r.seq, seen: r.seen.filter((id) => typeof id === "string" && MSG_ID_RE.test(id)).slice(-SEEN_KEPT) };
  } catch {
    return { ...EMPTY };
  }
}

/** The state for a supervisor; seq 0 and no ids when nothing (or nothing readable) is stored: the relay then replays everything it still has. */
export async function loadRelayState(kv: KeyValue, supervisorId: string): Promise<RelayStateRec> {
  if (!ID_RE.test(supervisorId)) throw new Error("relay state: supervisor id");
  return parseState(await kv.getItem(relayStateKey(supervisorId)));
}

/**
 * Persists what the session reports through onSeq. Writes are serialized and coalesced (the
 * newest state wins), the seq never goes back, a failed write is retried with the next frame
 * and reported: losing it costs a replay, which the ids and the daemon's own checks absorb.
 */
export class RelayStateWriter {
  private rec: RelayStateRec;
  private writing: Promise<void> | null = null;
  private dirty = false;

  constructor(
    private readonly kv: KeyValue,
    private readonly supervisorId: string,
    initial: RelayStateRec,
    private readonly onError: (e: unknown) => void = () => {},
  ) {
    this.rec = { seq: initial.seq, seen: initial.seen.slice(-SEEN_KEPT) };
  }

  get state(): RelayStateRec {
    return { seq: this.rec.seq, seen: [...this.rec.seen] };
  }

  /** The hook of RelaySession: a frame was handled and acked. */
  onSeq = (seq: number, id: string): void => {
    if (seq > this.rec.seq) this.rec.seq = seq;
    if (!this.rec.seen.includes(id)) {
      this.rec.seen.push(id);
      if (this.rec.seen.length > SEEN_KEPT) this.rec.seen.splice(0, this.rec.seen.length - SEEN_KEPT);
    }
    this.dirty = true;
    void this.flush();
  };

  /** Resolves when everything reported so far is written (or its write failed). */
  flush(): Promise<void> {
    this.writing ??= this.run().finally(() => {
      this.writing = null;
    });
    return this.writing;
  }

  private async run(): Promise<void> {
    while (this.dirty) {
      this.dirty = false;
      try {
        await this.kv.setItem(relayStateKey(this.supervisorId), JSON.stringify(this.rec));
      } catch (e) {
        this.onError(e);
        return;
      }
    }
  }
}
