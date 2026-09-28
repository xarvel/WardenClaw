// SPDX-License-Identifier: GPL-3.0-or-later
import React, { useEffect } from "react";
import { StatusBar } from "expo-status-bar";
import { Linking, View, useColorScheme } from "react-native";
import { NavigationContainer, DarkTheme, DefaultTheme, createNavigationContainerRef } from "@react-navigation/native";
import { BottomTabBar, createBottomTabNavigator } from "@react-navigation/bottom-tabs";
import { SafeAreaProvider } from "react-native-safe-area-context";
import Ionicons from "@expo/vector-icons/Ionicons";
import FeedScreen from "./src/ui/screens/FeedScreen";
import ModeScreen from "./src/ui/screens/ModeScreen";
import JournalScreen from "./src/ui/screens/JournalScreen";
import ConnectScreen from "./src/ui/screens/ConnectScreen";
import { bootstrap } from "./src/core/controller";
import { initBackground, syncBackground } from "./src/core/background";
import { routeLink } from "./src/core/links";
import { initPhonePush } from "./src/core/phonePush";
import { useAppState, pushLog, setState } from "./src/core/store";
import { usePalette } from "./src/ui/theme";
import { useT } from "./src/ui/i18n";
import { AutopilotBanner, PrivacyShield } from "./src/ui/Guards";

// Benchmark, mock cards and the screen protection toggle exist only in the bench build: elsewhere
// the condition folds to false at build time, and Metro leaves src/bench/entry out of the bundle.
const bench: typeof import("./src/bench/entry") | null = process.env.EXPO_PUBLIC_WARDENCLAW_BENCH === "1" ? require("./src/bench/entry") : null;
// Phone judge (Experimental) is outside the first release: without the build flag src/localjudge
// and the model engines stay out of the bundle (features.js, docs/release-scope.md).
const phoneJudge: typeof import("./src/localjudge/entry") | null = process.env.EXPO_PUBLIC_WARDENCLAW_FEATURE_PHONE_JUDGE === "1" ? require("./src/localjudge/entry") : null;

type Tabs = { feed: undefined; mode: undefined; journal: undefined; connect: undefined };
const Tab = createBottomTabNavigator<Tabs>();
const nav = createNavigationContainerRef<Tabs>();

const ICONS = { feed: "list", mode: "shield-checkmark", journal: "time", connect: "link" } as const;

/** Tap on a notification (Android) or push (iPhone): card → "Feed" tab, card expanded. */
function openCard(id: string) {
  setState({ focusCardId: id });
  if (nav.isReady()) nav.navigate("feed");
}

/**
 * Any app can open a wardenclaw:// link, so the link does nothing by itself (links.ts):
 * feed?card=<id> → the card; feed (digest, "Expired") → the feed with "Missed"; pair?… (QR scanned
 * by the system camera) → "Connect" with the link in the field, connecting on tap and with owner
 * confirmation; bench?… only in the bench build.
 */
function openFromUrl(url: string | null) {
  const r = routeLink(url, { bench: !!bench });
  if (!r) return;
  switch (r.kind) {
    case "bench":
      bench?.handleBenchUrl(r.url).catch((e) => pushLog(`bench: ${String(e?.message ?? e)}`));
      return;
    case "pair":
      setState({ pendingPairLink: r.link });
      if (nav.isReady()) nav.navigate("connect");
      return;
    case "card":
      openCard(r.id);
      return;
    case "feed":
      if (nav.isReady()) nav.navigate("feed");
  }
}

export default function App() {
  const scheme = useColorScheme();
  const p = usePalette();
  const t = useT();
  const cards = useAppState((s) => s.cards.length);
  useEffect(() => {
    bootstrap()
      .then(() => {
        initBackground();
        syncBackground();
        initPhonePush(openCard);
      })
      .then(() => phoneJudge?.loadLocalJudgeSettings())
      .then(() => (phoneJudge?.getLJ().enabled ? phoneJudge.refreshLocalModels() : undefined))
      .then(() => bench?.initBenchScreen())
      .catch((e) => pushLog(`bootstrap: ${String(e?.message ?? e)}`));
    Linking.getInitialURL().then(openFromUrl).catch(() => {});
    const sub = Linking.addEventListener("url", (e) => openFromUrl(e.url));
    return () => sub.remove();
  }, []);

  const navTheme = scheme === "dark" ? { ...DarkTheme, colors: { ...DarkTheme.colors, background: p.bg, card: p.card, border: p.border, primary: p.accent } } : { ...DefaultTheme, colors: { ...DefaultTheme.colors, background: p.bg, card: p.card, border: p.border, primary: p.accent } };

  return (
    <SafeAreaProvider>
      <NavigationContainer ref={nav} theme={navTheme}>
        <Tab.Navigator
          tabBar={(props) => (
            <View>
              <AutopilotBanner />
              <BottomTabBar {...props} />
            </View>
          )}
          screenOptions={({ route }) => ({
            headerShown: false,
            tabBarActiveTintColor: p.accent,
            tabBarInactiveTintColor: p.muted,
            tabBarLabelStyle: { fontSize: 12, fontWeight: "600" },
            tabBarIcon: ({ color, size }) => <Ionicons name={ICONS[route.name]} size={size} color={color} />,
          })}
        >
          <Tab.Screen name="feed" component={FeedScreen} options={{ title: t("tab.feed"), tabBarBadge: cards > 0 ? cards : undefined }} />
          <Tab.Screen name="mode" component={ModeScreen} options={{ title: t("tab.mode") }} />
          <Tab.Screen name="journal" component={JournalScreen} options={{ title: t("tab.journal") }} />
          <Tab.Screen name="connect" component={ConnectScreen} options={{ title: t("tab.connect") }} />
        </Tab.Navigator>
      </NavigationContainer>
      {bench ? <bench.BenchModal /> : null}
      <PrivacyShield />
      <StatusBar style="auto" />
    </SafeAreaProvider>
  );
}
