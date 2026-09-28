// SPDX-License-Identifier: AGPL-3.0-or-later
// Presence: a device is told whether the supervisor is connected, right after its welcome and
// whenever the supervisor's connection opens or closes.

import { beforeEach, describe, expect, it } from "vitest";
import { login, party, sleep, type Party, type Sock } from "./helpers";

let sup: Party;
let dev: Party;

beforeEach(async () => {
  sup = await party();
  dev = await party();
});

async function peers(s: Sock, n: number): Promise<boolean[]> {
  for (let i = 0; i < 100 && s.peers.length < n; i++) await sleep(10);
  return s.peers;
}

describe("presence", () => {
  it("tells a device that the supervisor is away, comes, and leaves", async () => {
    const D = await login(sup.id, dev, "device");
    expect(await peers(D, 1)).toEqual([false]);

    const S = await login(sup.id, sup, "supervisor");
    expect(await peers(D, 2)).toEqual([false, true]);
    expect(S.peers).toEqual([]);

    S.ws.close(1000, "bye");
    expect(await peers(D, 3)).toEqual([false, true, false]);
    await sleep(100);
    expect(D.peers.length).toBe(3);
  });

  it("tells a device that connects later, also one that is not trusted", async () => {
    await login(sup.id, sup, "supervisor");
    const D = await login(sup.id, dev, "device");
    expect(await peers(D, 1)).toEqual([true]);
    await D.expectNone(100);
  });

  it("a supervisor that reconnects over its old socket stays online", async () => {
    const S1 = await login(sup.id, sup, "supervisor");
    const D = await login(sup.id, dev, "device");
    const S2 = await login(sup.id, sup, "supervisor");
    for (let i = 0; i < 100 && !S1.closed; i++) await sleep(10);
    expect(S1.closed?.code).toBe(4001);
    await sleep(100);
    expect(D.peers).toEqual([true, true]);

    S2.ws.close(1000, "bye");
    expect(await peers(D, 3)).toEqual([true, true, false]);
  });

  it("a device that leaves changes nothing for the others", async () => {
    await login(sup.id, sup, "supervisor");
    const D = await login(sup.id, dev, "device");
    const O = await login(sup.id, await party(), "device");
    O.ws.close(1000, "bye");
    await sleep(100);
    expect(D.peers).toEqual([true]);
  });
});
