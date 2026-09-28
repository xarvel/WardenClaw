// SPDX-License-Identifier: GPL-3.0-or-later
// The feed screen: the list of cards, the offline banner, and the empty state.
// A card itself lives in ../feed/CardView.
import { useEffect, useRef, useState } from "react";
import { FlatList, Text, View, type ViewToken } from "react-native";
import { useIsFocused } from "@react-navigation/native";
import { SafeAreaView } from "react-native-safe-area-context";
import { StatusPill } from "../components";
import { usePalette } from "../theme";
import { useT } from "../i18n";
import { decisionPathOpen, linkFault } from "../../core/serverMode";
import { useAppState } from "../../core/store";
import type { Card } from "../../core/approvals";
import { CardView } from "../feed/CardView";
import { MissedBlock, Snackbar, UnshownBlock } from "../feed/FeedChrome";
import { FAULT_TITLE, emptyHint, faultBody } from "../feed/statusCopy";
import { styles } from "../feed/styles";
import { GUARD_MS, LEAVE_GRACE_MS, LEAVE_MERGE_BUFFER_MS, LEAVE_MS } from "../feed/timing";

// The on-phone judge is outside the first release. Without the flag its code stays out of the bundle.
const phoneJudge: typeof import("../../localjudge/entry") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE === "1" ? require("../../localjudge/entry") : null;

type Item = { card: Card; leaving: boolean; leftAt: number };

function merge(prev: Item[], cards: Card[], now: number): Item[] {
  const ids = new Set(cards.map((c) => c.id));
  const out: Item[] = cards.map((card) => ({ card, leaving: false, leftAt: 0 }));
  prev.forEach((it, idx) => {
    if (ids.has(it.card.id)) return;
    const leftAt = it.leaving ? it.leftAt : now;
    if (now - leftAt > LEAVE_MS + LEAVE_GRACE_MS) return;
    out.splice(Math.min(idx, out.length), 0, { card: it.card, leaving: true, leftAt });
  });
  return out;
}

const VIEWABILITY = { itemVisiblePercentThreshold: 40, minimumViewTime: 300 };

export default function FeedScreen() {
  const p = usePalette();
  const t = useT();
  const focusCardId = useAppState((s) => s.focusCardId);
  const listRef = useRef<FlatList<Item>>(null);
  const cards = useAppState((s) => s.cards);
  const wardend = useAppState((s) => s.wardend);
  const status = useAppState((s) => s.status);
  const openclawAdapter = useAppState((s) => s.openclawAdapter);
  // while the snackbar is shown, the bottom of the feed can be scrolled above it: it no longer lets
  // touches through
  const snackShown = useAppState((s) => s.snack !== null);
  const gatewayUp = openclawAdapter && status === "connected";
  const wardendUp = wardend.status === "connected";
  const hint = emptyHint(wardend.status, wardend.mode, wardend.policyMode, wardend.lastReason, wardend.lastError, wardend.host, gatewayUp);
  const wardendFault = linkFault(wardend.status, wardend.lastReason);
  const liveCards = cards.filter((c) => !c.mock);
  const wardendBlocked = liveCards.some((c) => c.gate?.via === "wardend" && !wardendUp);
  const gatewayBlocked = liveCards.some((c) => c.gate?.via !== "wardend" && !gatewayUp);
  const [now, setNow] = useState(Date.now());
  const [items, setItems] = useState<Item[]>(() => cards.map((card) => ({ card, leaving: false, leftAt: 0 })));
  const guard = useRef(new Map<string, number>());
  const lastIndex = useRef(new Map<string, number>());

  useEffect(() => {
    setItems((prev) => merge(prev, cards, Date.now()));
    const tm = setTimeout(() => setItems((prev) => merge(prev, cards, Date.now())), LEAVE_MS + LEAVE_MERGE_BUFFER_MS);
    return () => clearTimeout(tm);
  }, [cards]);

  // A card shifted (neighbour above left, a new one appeared): its buttons do not respond for 700 ms.
  const now0 = Date.now();
  items.forEach((it, idx) => {
    if (it.leaving) return;
    const prevIdx = lastIndex.current.get(it.card.id);
    const collapsingAbove = items.slice(0, idx).some((x) => x.leaving);
    if (prevIdx === undefined || prevIdx !== idx || collapsingAbove) {
      guard.current.set(it.card.id, Math.max(guard.current.get(it.card.id) ?? 0, now0 + (collapsingAbove ? LEAVE_MS : 0) + GUARD_MS));
    }
    lastIndex.current.set(it.card.id, idx);
  });

  // Experimental: the local judge computes an opinion only for cards visible on the feed screen.
  const focused = useIsFocused();
  useEffect(() => {
    phoneJudge?.setFeedFocused(focused);
    return () => phoneJudge?.setFeedFocused(false);
  }, [focused]);
  const onViewable = useRef(({ viewableItems }: { viewableItems: ViewToken<Item>[] }) => {
    phoneJudge?.setVisibleCards(viewableItems.filter((v) => v.isViewable && v.item && !v.item.leaving).map((v) => (v.item as Item).card.id));
  }).current;
  useEffect(() => {
    if (!cards.length) phoneJudge?.setVisibleCards([]);
  }, [cards.length]);
  // Opened from a notification: scroll to the card (it expands in CardView)
  useEffect(() => {
    if (!focusCardId) return;
    const i = items.findIndex((c) => c.card.id === focusCardId);
    if (i >= 0) listRef.current?.scrollToIndex({ index: i, animated: true, viewPosition: 0 });
  }, [focusCardId, items]);
  useEffect(() => {
    const tm = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(tm);
  }, []);

  return (
    <SafeAreaView style={[styles.screen, { backgroundColor: p.bg }]} edges={["top"]}>
      <View style={styles.header}>
        <Text style={[styles.h1, { color: p.text }]}>{t("tab.feed")}</Text>
        <StatusPill />
      </View>
      <FlatList
        ref={listRef}
        data={items}
        keyExtractor={(it) => it.card.id}
        renderItem={({ item }) => (
          <CardView
            card={item.card}
            now={now}
            focused={item.card.id === focusCardId}
            leaving={item.leaving}
            guardUntil={guard.current.get(item.card.id) ?? 0}
            offline={!decisionPathOpen(item.card.gate?.via, !!item.card.mock, wardendUp, gatewayUp)}
          />
        )}
        extraData={{ now, wardendUp, gatewayUp, wardendFault }}
        onScrollToIndexFailed={() => {}}
        onViewableItemsChanged={onViewable}
        viewabilityConfig={VIEWABILITY}
        contentContainerStyle={{ padding: 16, paddingBottom: snackShown ? 160 : 80, flexGrow: 1 }}
        ListHeaderComponent={
          <>
            {wardendBlocked && wardendFault ? (
              <View style={[styles.missed, { borderColor: p.warn, backgroundColor: p.card }]} accessibilityRole="alert">
                <Text style={{ color: p.text, fontSize: 15, fontWeight: "700" }}>{t(FAULT_TITLE[wardendFault])}</Text>
                <Text style={{ color: p.muted, fontSize: 13, marginTop: 4 }}>{faultBody(wardendFault, wardend.lastError, wardend.host)}</Text>
              </View>
            ) : null}
            {gatewayBlocked ? (
              <View style={[styles.missed, { borderColor: p.warn, backgroundColor: p.card }]} accessibilityRole="alert">
                <Text style={{ color: p.text, fontSize: 15, fontWeight: "700" }}>{t("feed.fault.gateway")}</Text>
              </View>
            ) : null}
            <UnshownBlock />
            <MissedBlock />
          </>
        }
        ListEmptyComponent={
          <View style={styles.empty}>
            <Text style={[styles.emptyTitle, { color: p.text }]}>{t("feed.empty")}</Text>
            <Text style={[styles.emptyHint, { color: p.muted }]}>{hint}</Text>
          </View>
        }
      />
      <Snackbar />
    </SafeAreaView>
  );
}
