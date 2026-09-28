// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import ExpoModulesCore
import UIKit

public final class BenchProbeModule: Module {
  public func definition() -> ModuleDefinition {
    Name("BenchProbe")

    OnCreate {
      DispatchQueue.main.async {
        UIDevice.current.isBatteryMonitoringEnabled = true
      }
    }

    Function("snapshot") { () -> [String: Any] in
      let device = UIDevice.current
      let level = device.batteryLevel >= 0 ? Double(device.batteryLevel) * 100.0 : -1.0
      let state = device.batteryState
      let plugged: Int
      switch state {
      case .charging, .full: plugged = 1
      case .unplugged: plugged = 0
      default: plugged = -1
      }
      return [
        "platform": "ios",
        "ts": Date().timeIntervalSince1970 * 1000.0,
        "levelPct": level,
        // Public iOS APIs expose neither current nor charge counter nor temperature.
        "chargeUah": 0.0,
        "currentUa": 0.0,
        "energyNwh": 0.0,
        "tempC": -1.0,
        "voltageMv": -1,
        "plugged": plugged,
        "status": state.rawValue,
        "thermalStatus": ProcessInfo.processInfo.thermalState.rawValue,
        "thermalHeadroom": -1.0,
        "currentSupported": false,
        "temperatureSupported": false,
        "physicalMemoryMb": Double(ProcessInfo.processInfo.physicalMemory) / 1_048_576.0,
      ]
    }

    Function("log") { (tag: String, line: String) in
      // Only the bench build (Info.plist WardenClawBench, plugins/withAppHardening.js) writes the
      // benchmark log to the system log: it carries deep-link URLs and command prefixes.
      guard Bundle.main.object(forInfoDictionaryKey: "WardenClawBench") as? Bool == true else { return }
      let chunk = 3_500
      if line.count <= chunk {
        NSLog("%@ %@", tag, line)
        return
      }
      var start = line.startIndex
      var i = 1
      let parts = Int(ceil(Double(line.count) / Double(chunk)))
      while start < line.endIndex {
        let end = line.index(start, offsetBy: chunk, limitedBy: line.endIndex) ?? line.endIndex
        NSLog("%@ [%d/%d]%@", tag, i, parts, String(line[start..<end]))
        start = end
        i += 1
      }
    }

    AsyncFunction("sha256File") { (path: String) -> String in
      let url: URL
      if path.hasPrefix("file://"), let parsed = URL(string: path) { url = parsed }
      else { url = URL(fileURLWithPath: path) }
      let file = try FileHandle(forReadingFrom: url)
      defer { try? file.close() }
      var hash = SHA256()
      while let data = try file.read(upToCount: 1 << 20), !data.isEmpty {
        hash.update(data: data)
      }
      return hash.finalize().map { String(format: "%02x", $0) }.joined()
    }

    Function("keepScreenOn") { (on: Bool) -> Bool in
      DispatchQueue.main.async { UIApplication.shared.isIdleTimerDisabled = on }
      return true
    }
  }
}
