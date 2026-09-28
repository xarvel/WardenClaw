// SPDX-License-Identifier: GPL-3.0-or-later
import { Platform, useColorScheme } from "react-native";

export type Palette = {
  bg: string;
  card: string;
  border: string;
  text: string;
  muted: string;
  accent: string;
  // text and icons on the accent fill (segments, filters, buttons): at least 4.5:1
  accentText: string;
  allow: string;
  allowText: string;
  deny: string;
  denyText: string;
  warn: string;
  ok: string;
  badgeExec: string;
  badgePlugin: string;
  badgeGate: string;
  input: string;
  disabled: string;
  // risk chips: background and text with a contrast of at least 4.5:1
  riskLow: string;
  riskLowText: string;
  riskMid: string;
  riskMidText: string;
  riskHigh: string;
  riskHighText: string;
  unrated: string;
  unratedText: string;
  // dangerous card: border, reason text and banner background
  danger: string;
  dangerBg: string;
  // hold-to-"Allow" on a dangerous card: amber border and solid fill, the label over the fill is
  // inverted (hold on card and holdText on hold at least 4.5:1, the fill against the empty part too)
  hold: string;
  holdText: string;
};

const light: Palette = {
  bg: "#F4F5F7",
  card: "#FFFFFF",
  border: "#E1E4EA",
  text: "#14171F",
  muted: "#5F6672",
  accent: "#2F6FED",
  accentText: "#FFFFFF",
  allow: "#17803F",
  allowText: "#FFFFFF",
  deny: "#C53030",
  denyText: "#FFFFFF",
  warn: "#9A6700",
  ok: "#17803F",
  badgeExec: "#E8EEFC",
  badgePlugin: "#F1E8FC",
  badgeGate: "#FCEFD9",
  input: "#FFFFFF",
  disabled: "#C9CDD4",
  riskLow: "#17803F",
  riskLowText: "#FFFFFF",
  riskMid: "#9A6700",
  riskMidText: "#FFFFFF",
  riskHigh: "#B42318",
  riskHighText: "#FFFFFF",
  unrated: "#E1E4EA",
  unratedText: "#14171F",
  danger: "#B42318",
  dangerBg: "#FDECEC",
  hold: "#9A6700",
  holdText: "#FFFFFF",
};

const dark: Palette = {
  bg: "#0F1115",
  card: "#1A1D24",
  border: "#2A2F3A",
  text: "#EDEFF3",
  muted: "#9AA1AE",
  accent: "#6B9BFF",
  accentText: "#0B1530",
  allow: "#2BB673",
  allowText: "#06130C",
  deny: "#E5605E",
  denyText: "#180606",
  warn: "#E2B04A",
  ok: "#2BB673",
  badgeExec: "#22304F",
  badgePlugin: "#37264F",
  badgeGate: "#4A3A1E",
  input: "#12151B",
  disabled: "#3A3F4A",
  riskLow: "#2BB673",
  riskLowText: "#06130C",
  riskMid: "#E2B04A",
  riskMidText: "#06130C",
  riskHigh: "#E5605E",
  riskHighText: "#180606",
  unrated: "#3A3F4A",
  unratedText: "#EDEFF3",
  danger: "#F07470",
  dangerBg: "#3A1D1F",
  hold: "#E2B04A",
  holdText: "#1A1D24",
};

export function usePalette(): Palette {
  return useColorScheme() === "dark" ? dark : light;
}

/**
 * Fonts. Commands, argv, fingerprints and the journal are set in monospace: the difference between
 * l/1/I, 0/O and the spaces between arguments is what the signed facts mean. iOS has no "monospace"
 * family, RN silently takes proportional SF Pro; the system alias "ui-monospace" gives SF Mono
 * (ux-visual V-11).
 */
export const fonts: { mono: string } = {
  mono: Platform.select({ ios: "ui-monospace", default: "monospace" }),
};
