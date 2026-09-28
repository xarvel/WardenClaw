// SPDX-License-Identifier: GPL-3.0-or-later
// Journal: append-only SQLite, each entry carries prev_hash and hash = sha256(prev_hash + canonicalJSON(entry)).
import { errMsg } from "./errMsg";
import * as SQLite from "expo-sqlite";
import { push } from "../../modules/wardenpush";
import { canonicalJson, sha256Hex } from "./canonical";
import { journalMsg } from "./journalText";

export { canonicalJson };

export type JournalKind = "requested" | "verdict" | "resolved" | "auto_resolved" | "expired" | "connect" | "pairing" | "escalation" | "error" | "info" | "local_opinion";
export type DecidedBy = "me" | "other" | "timeout" | "agent" | null;

export type JournalEntry = {
  id: number;
  ts: number;
  kind: JournalKind;
  approval_id: string | null;
  approval_kind: string | null;
  summary: string;
  decided_by: DecidedBy;
  decision: string | null;
  latency_ms: number | null;
  payload: string | null;
  prev_hash: string;
  hash: string;
};

export type NewEntry = Omit<JournalEntry, "id" | "prev_hash" | "hash">;

const GENESIS = "0".repeat(64);
let db: SQLite.SQLiteDatabase | null = null;
let lastHash: string = GENESIS;
const listeners = new Set<() => void>();

/**
 * iOS: the database lives in Documents/SQLite (the expo-sqlite default directory), and Documents
 * goes into the iCloud backup (privacy H-4). The database directory is excluded from backup by an
 * attribute (modules/wardenpush) after opening, i.e. once the directory exists, and so on every
 * start. On Android there is no module: backup is disabled entirely there (android.allowBackup in
 * app.json). A failure does not stop the journal from working.
 */
function excludeJournalFromBackup() {
  try {
    const dir = SQLite.defaultDatabaseDirectory;
    if (typeof dir === "string" && dir && push?.excludeFromBackup && !push.excludeFromBackup(dir)) console.warn("journal: could not exclude the database directory from backup");
  } catch (e) {
    console.warn(`journal: exclude from backup: ${errMsg(e)}`);
  }
}

export function initJournal() {
  if (db) return;
  db = SQLite.openDatabaseSync("wardenclaw.db");
  excludeJournalFromBackup();
  db.execSync(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts INTEGER NOT NULL,
      kind TEXT NOT NULL,
      approval_id TEXT,
      approval_kind TEXT,
      summary TEXT NOT NULL,
      decided_by TEXT,
      decision TEXT,
      latency_ms INTEGER,
      payload TEXT,
      prev_hash TEXT NOT NULL,
      hash TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS events_ts ON events(ts DESC);
    CREATE INDEX IF NOT EXISTS events_approval ON events(approval_id);
  `);
  const last = db.getFirstSync<{ hash: string }>("SELECT hash FROM events ORDER BY id DESC LIMIT 1");
  lastHash = last?.hash ?? GENESIS;
}

/** The row itself, chained to the current head; listeners are told by the caller. */
function insertEntry(e: NewEntry): JournalEntry {
  const prev_hash = lastHash;
  const body = { ...e, prev_hash };
  const hash = sha256Hex(prev_hash + canonicalJson(body));
  const res = db!.runSync(
    "INSERT INTO events (ts, kind, approval_id, approval_kind, summary, decided_by, decision, latency_ms, payload, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    [e.ts, e.kind, e.approval_id, e.approval_kind, e.summary, e.decided_by, e.decision, e.latency_ms, e.payload, prev_hash, hash],
  );
  lastHash = hash;
  return { ...e, id: Number(res.lastInsertRowId), prev_hash, hash };
}

export function appendEntry(e: NewEntry): JournalEntry {
  if (!db) initJournal();
  const entry = insertEntry(e);
  for (const l of listeners) l();
  return entry;
}

export function countEntries(): number {
  if (!db) initJournal();
  return Number(db!.getFirstSync<{ n: number }>("SELECT COUNT(*) AS n FROM events")?.n ?? 0);
}

/**
 * The owner clears the journal. One transaction deletes every row, restarts the chain from GENESIS
 * and writes the first entry of the new chain, which records the wipe: how many entries went and the
 * hash of the old head. A cleared journal therefore never looks pristine. Only this phone is
 * affected: the server keeps its own journal. Row ids keep counting (AUTOINCREMENT), so the first
 * entry of the new chain does not have id 1 either.
 */
export function clearJournal(): { removed: number; previousHead: string; entry: JournalEntry } {
  if (!db) initJournal();
  const previousHead = lastHash;
  const done: { removed: number; entry: JournalEntry | null } = { removed: 0, entry: null };
  try {
    db!.withTransactionSync(() => {
      done.removed = countEntries();
      db!.runSync("DELETE FROM events");
      lastHash = GENESIS;
      done.entry = insertEntry({ ts: Date.now(), kind: "info", approval_id: null, approval_kind: null, ...journalMsg("j.cleared", { n: done.removed, head: previousHead.slice(0, 16) }, { removed: done.removed, previousHead }), decided_by: null, decision: null, latency_ms: null });
    });
  } catch (e) {
    lastHash = previousHead; // rolled back: the old chain is still there
    throw e;
  }
  if (!done.entry) throw new Error("journal: the wipe entry was not written");
  for (const l of listeners) l();
  return { removed: done.removed, previousHead, entry: done.entry };
}

export function listEntries(opts: { decidedBy?: DecidedBy | "all"; search?: string; limit?: number } = {}): JournalEntry[] {
  if (!db) initJournal();
  const where: string[] = [];
  const args: (string | number)[] = [];
  if (opts.decidedBy && opts.decidedBy !== "all") {
    where.push("decided_by = ?");
    args.push(opts.decidedBy);
  }
  const q = opts.search?.trim();
  if (q) {
    where.push("(summary LIKE ? OR payload LIKE ? OR approval_id LIKE ?)");
    const like = `%${q}%`;
    args.push(like, like, like);
  }
  const sql = `SELECT * FROM events ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY id DESC LIMIT ${opts.limit ?? 500}`;
  return db!.getAllSync<JournalEntry>(sql, args);
}

/** Chain integrity check: returns the id of the first broken entry, or null. */
export function verifyChain(): number | null {
  if (!db) initJournal();
  const rows = db!.getAllSync<JournalEntry>("SELECT * FROM events ORDER BY id ASC");
  let prev = GENESIS;
  for (const r of rows) {
    const { id: _id, hash, prev_hash, ...rest } = r;
    if (prev_hash !== prev) return r.id;
    const expected = sha256Hex(prev_hash + canonicalJson({ ...rest, prev_hash }));
    if (expected !== hash) return r.id;
    prev = hash;
  }
  return null;
}

export function subscribeJournal(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}
