// SPDX-License-Identifier: GPL-3.0-or-later
// Hold-to-allow on a dangerous card. A screen reader gets a confirm dialog instead of the hold.
import { useEffect, useRef, useState } from "react";
import { AccessibilityInfo, Alert, Animated, Easing, Pressable, Text, View } from "react-native";
import * as Haptics from "expo-haptics";
import { usePalette } from "../theme";
import { useT } from "../i18n";
import { styles } from "./styles";
import { DIALOG_DEBOUNCE_MS, HOLD_MS, TOUCH_PRESS_GAP_MS } from "./timing";

// ---------------------------------------------------------------------------
// Hold-to-"Allow" (dangerous cards), like on the watch
// ---------------------------------------------------------------------------
/** Whether a screen reader is on (TalkBack, VoiceOver): then the hold button opens a dialog. */
function useScreenReader(): boolean {
  const [on, setOn] = useState(false);
  useEffect(() => {
    let alive = true;
    AccessibilityInfo.isScreenReaderEnabled()
      .then((v) => {
        if (alive) setOn(v);
      })
      .catch(() => {});
    const sub = AccessibilityInfo.addEventListener("screenReaderChanged", setOn);
    return () => {
      alive = false;
      sub.remove();
    };
  }, []);
  return on;
}

/**
 * 1.5 s hold (ux-visual V-21, ux-copy A-1, A-17): amber border and a solid fill from left to right,
 * the label over the fill is inverted (the second text layer is clipped to the fill width), the
 * second label line changes ("hold 1.5 s", "keep holding…", "allowing…"). Vibration: a click at the
 * start, light at 0.5 and 1.0 s, heavy at completion (before the network), "success" after the
 * server response (decided). Early release: the button shakes, a warning vibration and a hint under
 * the buttons. Screen reader and Switch Access: the activate action and a click without a hold open
 * the "Allow the dangerous command?" dialog with "Cancel", then the usual owner confirmation; it
 * does not fire by accident, yet a dangerous command can be allowed without the hold gesture.
 */
export function HoldButton({ title, disabled, busy, host, what, onConfirm, onEarly }: { title: string; disabled?: boolean; busy: boolean; host: string | null; what: string; onConfirm: () => void; onEarly: () => void }) {
  const p = usePalette();
  const t = useT();
  const screenReader = useScreenReader();
  const progress = useRef(new Animated.Value(0)).current;
  const shake = useRef(new Animated.Value(0)).current;
  const anim = useRef<Animated.CompositeAnimation | null>(null);
  const fired = useRef(false);
  const pressInAt = useRef(0);
  const pressOutAt = useRef(0);
  const lastDialogAt = useRef(0);
  const ticks = useRef<ReturnType<typeof setTimeout>[]>([]);
  const [phase, setPhase] = useState<"idle" | "holding" | "done">("idle");
  const [size, setSize] = useState({ w: 0, h: 0 });
  const clearTicks = () => {
    for (const tm of ticks.current) clearTimeout(tm);
    ticks.current = [];
  };
  useEffect(() => () => clearTicks(), []);
  // "allowing…" until the server responds; if the decision did not go out (confirmation cancelled,
  // error, key): back to idle
  useEffect(() => {
    if (phase !== "done" || busy) return;
    const tm = setTimeout(() => {
      fired.current = false;
      setPhase("idle");
      progress.setValue(0);
    }, 400);
    return () => clearTimeout(tm);
  }, [phase, busy, progress]);

  const confirmNow = () => {
    fired.current = true;
    clearTicks();
    Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Heavy).catch(() => {});
    progress.setValue(1);
    setPhase("done");
    onConfirm();
  };
  const start = () => {
    if (disabled || busy) return;
    fired.current = false;
    pressInAt.current = Date.now();
    setPhase("holding");
    Haptics.selectionAsync().catch(() => {});
    clearTicks();
    for (const ms of [HOLD_MS / 3, (HOLD_MS * 2) / 3]) ticks.current.push(setTimeout(() => Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light).catch(() => {}), ms));
    anim.current = Animated.timing(progress, { toValue: 1, duration: HOLD_MS, easing: Easing.linear, useNativeDriver: false });
    anim.current.start(({ finished }) => {
      if (finished && !fired.current) confirmNow();
    });
  };
  const cancel = () => {
    pressOutAt.current = Date.now();
    anim.current?.stop();
    clearTicks();
    if (fired.current || disabled || busy) return;
    setPhase("idle");
    Animated.timing(progress, { toValue: 0, duration: 150, useNativeDriver: false }).start();
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning).catch(() => {});
    Animated.sequence([4, -4, 4, 0].map((x) => Animated.timing(shake, { toValue: x, duration: 50, useNativeDriver: false }))).start();
    onEarly();
  };
  const openDialog = () => {
    if (disabled || busy) return;
    const now = Date.now();
    if (now - lastDialogAt.current < DIALOG_DEBOUNCE_MS) return;
    lastDialogAt.current = now;
    Alert.alert(host ? t("feed.hold.confirmTitle", { host }) : t("feed.hold.confirmTitleNoHost"), t("feed.hold.confirmBody", { what }), [
      { text: t("common.cancel"), style: "cancel" },
      { text: title, style: "destructive", onPress: confirmNow },
    ]);
  };
  // With a finger the hold decides: onPress comes after onPressIn (for a short touch Pressable delays
  // onPressOut by 130 ms, so we check both). A click without a touch (TalkBack, Switch Access, Voice
  // Access) or a touch with a screen reader on opens the dialog.
  const onPress = () => {
    const now = Date.now();
    const touch = now - pressInAt.current < HOLD_MS * 2 || now - pressOutAt.current < TOUCH_PRESS_GAP_MS;
    if (touch && (fired.current || !screenReader)) return;
    openDialog();
  };

  const border = disabled ? p.disabled : p.hold;
  const sub = phase === "done" || busy ? t("feed.hold.done") : phase === "holding" ? t("feed.hold.holding") : t("feed.hold.sub");
  const label = (color: string) => (
    <>
      <Text style={[styles.bigBtnText, { color, fontSize: 17 }]} numberOfLines={1} adjustsFontSizeToFit minimumFontScale={0.7}>
        {title}
      </Text>
      <Text style={{ color, fontSize: 12, fontWeight: "500", marginTop: 2 }} numberOfLines={1}>
        {sub}
      </Text>
    </>
  );
  // the fill and the second label layer inside the 2 dp border
  const inner = { w: Math.max(0, size.w - 4), h: Math.max(0, size.h - 4) };
  const width = progress.interpolate({ inputRange: [0, 1], outputRange: [0, inner.w] });
  return (
    <Animated.View style={{ flex: 1, transform: [{ translateX: shake }] }}>
      <Pressable
        onPressIn={start}
        onPressOut={cancel}
        onPress={onPress}
        pressRetentionOffset={{ top: 40, bottom: 40, left: 40, right: 40 }}
        disabled={disabled}
        onLayout={(e) => setSize({ w: e.nativeEvent.layout.width, h: e.nativeEvent.layout.height })}
        style={[styles.bigBtn, styles.holdBtn, { borderColor: border }]}
        accessibilityRole="button"
        accessibilityLabel={title}
        accessibilityHint={t("feed.hold.a11yHint")}
        accessibilityState={{ disabled: !!disabled, busy }}
        accessibilityActions={[{ name: "activate", label: title }]}
        onAccessibilityAction={(e) => {
          if (e.nativeEvent.actionName === "activate") openDialog();
        }}
        testID="hold-allow"
      >
        {label(disabled ? p.muted : p.hold)}
        <Animated.View pointerEvents="none" style={[styles.holdFill, { width, backgroundColor: p.hold }]}>
          <View style={[styles.holdInverse, { width: inner.w, height: inner.h }]}>{label(p.holdText)}</View>
        </Animated.View>
      </Pressable>
    </Animated.View>
  );
}
