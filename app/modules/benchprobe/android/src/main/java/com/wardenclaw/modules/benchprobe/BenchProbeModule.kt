// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.benchprobe

// "Judge benchmark" spike: battery/temperature measurements and results output to logcat.
//   snapshot()           level, charge counter (µAh), current_now (µA), temperature, power source, thermal status
//   log(tag, line)       Log.i split into chunks of ≤3500 chars (logcat truncates long lines);
//                        bench build only (meta-data com.wardenclaw.BENCH, plugins/withAppHardening.js)
//   keepScreenOn(on)     FLAG_KEEP_SCREEN_ON on the current activity for the duration of a run
//   sha256File(path)     sha256 of the weights file (Experimental: checking the downloaded model),
//                        off the UI thread

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.util.Log
import android.view.WindowManager
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class BenchProbeModule : Module() {
  private val context: Context
    get() = appContext.reactContext?.applicationContext ?: throw IllegalStateException("React context is not available")

  // In a release build the benchmark log (deep link URL, command prefixes) is not written to logcat
  private val benchBuild: Boolean by lazy {
    try {
      @Suppress("DEPRECATION")
      context.packageManager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA).metaData?.getBoolean("com.wardenclaw.BENCH", false) == true
    } catch (e: Exception) {
      false
    }
  }

  override fun definition() = ModuleDefinition {
    Name("BenchProbe")

    Function("snapshot") {
      val ctx = context
      val bm = ctx.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
      val sticky: Intent? = ctx.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
      val level = sticky?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
      val scale = sticky?.getIntExtra(BatteryManager.EXTRA_SCALE, 100) ?: 100
      val tempTenths = sticky?.getIntExtra(BatteryManager.EXTRA_TEMPERATURE, Int.MIN_VALUE) ?: Int.MIN_VALUE
      val voltage = sticky?.getIntExtra(BatteryManager.EXTRA_VOLTAGE, -1) ?: -1
      val plugged = sticky?.getIntExtra(BatteryManager.EXTRA_PLUGGED, 0) ?: 0
      val status = sticky?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
      val pm = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
      val thermal = if (Build.VERSION.SDK_INT >= 29) pm.currentThermalStatus else -1
      val headroom = if (Build.VERSION.SDK_INT >= 30) pm.getThermalHeadroom(0).toDouble() else Double.NaN
      mapOf(
        "ts" to System.currentTimeMillis(),
        "levelPct" to (if (level >= 0 && scale > 0) level * 100.0 / scale else -1.0),
        "chargeUah" to bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_CHARGE_COUNTER).toDouble(),
        "currentUa" to bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_CURRENT_NOW).toDouble(),
        "energyNwh" to bm.getLongProperty(BatteryManager.BATTERY_PROPERTY_ENERGY_COUNTER).toDouble(),
        "tempC" to (if (tempTenths == Int.MIN_VALUE) Double.NaN else tempTenths / 10.0),
        "voltageMv" to voltage,
        "plugged" to plugged,
        "status" to status,
        "thermalStatus" to thermal,
        "thermalHeadroom" to (if (headroom.isNaN()) -1.0 else headroom)
      )
    }

    Function("log") { tag: String, line: String ->
      if (!benchBuild) return@Function
      val chunk = 3500
      if (line.length <= chunk) {
        Log.i(tag, line)
      } else {
        val parts = (line.length + chunk - 1) / chunk
        for (i in 0 until parts) {
          val end = minOf(line.length, (i + 1) * chunk)
          Log.i(tag, "[${i + 1}/$parts]" + line.substring(i * chunk, end))
        }
      }
    }

    AsyncFunction("sha256File") { path: String ->
      val md = java.security.MessageDigest.getInstance("SHA-256")
      val buf = ByteArray(1 shl 20)
      java.io.FileInputStream(java.io.File(path.removePrefix("file://"))).use { input ->
        while (true) {
          val n = input.read(buf)
          if (n < 0) break
          md.update(buf, 0, n)
        }
      }
      md.digest().joinToString("") { "%02x".format(it) }
    }

    Function("keepScreenOn") { on: Boolean ->
      val activity = appContext.currentActivity ?: return@Function false
      activity.runOnUiThread {
        if (on) activity.window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        else activity.window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
      }
      true
    }
  }
}
