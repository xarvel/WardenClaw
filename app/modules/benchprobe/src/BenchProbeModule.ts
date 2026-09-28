// SPDX-License-Identifier: GPL-3.0-or-later
// Native part (Kotlin, android/): battery and temperature measurements, log to logcat.
// In Expo Go, on iOS and web the module is absent: requireOptionalNativeModule returns null.
import { requireOptionalNativeModule } from "expo";

export type ProbeSnapshot = {
  platform?: "android" | "ios";
  ts: number;
  levelPct: number;
  chargeUah: number; // BATTERY_PROPERTY_CHARGE_COUNTER, µAh
  currentUa: number; // BATTERY_PROPERTY_CURRENT_NOW, µA (sign depends on the device)
  energyNwh: number; // often unsupported (Long.MIN_VALUE / 0)
  tempC: number; // battery temperature
  voltageMv: number;
  plugged: number; // 0 = on battery, 1 AC, 2 USB, 4 wireless
  status: number; // BatteryManager.BATTERY_STATUS_*
  thermalStatus: number; // PowerManager.THERMAL_STATUS_*
  thermalHeadroom: number; // getThermalHeadroom(0), 1.0 = throttling threshold
  currentSupported?: boolean;
  temperatureSupported?: boolean;
  physicalMemoryMb?: number;
};

export type NativeBenchProbe = {
  snapshot(): ProbeSnapshot;
  log(tag: string, line: string): void;
  keepScreenOn(on: boolean): boolean;
  /** Present only in builds after stage 8 of the spike; undefined on older ones. */
  sha256File?(path: string): Promise<string>;
};

export default requireOptionalNativeModule<NativeBenchProbe>("BenchProbe");
