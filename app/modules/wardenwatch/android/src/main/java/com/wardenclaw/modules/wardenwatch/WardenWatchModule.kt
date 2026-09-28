// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.wardenwatch

// JS API of the background service and local notifications (see WatchService, Notifier, IncomingActivity).
//   configure(texts)              notification and channel texts in the UI language
//   start() / stop()              foreground service specialUse; start → false if Android did not allow it
//   isRunning()
//   setStatus(title, text)        persistent notification: connected / no connection / not paired
//   update(json)                  requests: {pending:[…], expired:[…], fullScreen}, see Notifier.update
//   cancelAllRequests()           the app is open: remove request notifications and the "like a call" screen
//   notificationsEnabled()        POST_NOTIFICATIONS permission and the requests channel are not turned off
//   canUseFullScreenIntent() / openFullScreenSettings()   "like an incoming call" mode (Android 14+)
//   ignoringBatteryOptimizations() / requestIgnoreBatteryOptimizations()
//   openNotificationSettings()
//   setScreenSecure(on) / isBenchBuild()   screen protection (ScreenGuard): removable only in the bench build

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class WardenWatchModule : Module() {
  private val context: Context
    get() = appContext.reactContext?.applicationContext ?: throw IllegalStateException("React context is not available")

  /** Open a settings screen: from the activity if there is one, otherwise as a new task. */
  private fun launch(intent: Intent): Boolean {
    val activity = appContext.currentActivity
    return try {
      if (activity != null) activity.startActivity(intent) else context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
      true
    } catch (e: Exception) {
      Log.w("WardenWatch", "cannot open ${intent.action}", e)
      false
    }
  }

  override fun definition() = ModuleDefinition {
    Name("WardenWatch")

    Function("configure") { texts: Map<String, String> ->
      Notifier.saveTexts(context, texts)
      Notifier.ensureChannels(context)
      if (WatchService.running) Notifier.refreshOngoing(context)
    }

    Function("start") {
      WatchService.start(context)
    }

    Function("stop") {
      WatchService.stop(context)
    }

    Function("isRunning") {
      WatchService.running
    }

    Function("setStatus") { title: String, text: String ->
      Notifier.setStatus(context, title, text)
    }

    Function("update") { json: String ->
      Notifier.update(context, json)
    }

    Function("cancelAllRequests") {
      Notifier.cancelAll(context)
    }

    Function("notificationsEnabled") {
      Notifier.enabled(context) && Notifier.requestsChannelEnabled(context)
    }

    Function("canUseFullScreenIntent") {
      Notifier.canUseFullScreenIntent(context)
    }

    Function("openFullScreenSettings") {
      if (Build.VERSION.SDK_INT >= 34) {
        launch(Intent(Settings.ACTION_MANAGE_APP_USE_FULL_SCREEN_INTENT, Uri.parse("package:" + context.packageName)))
      } else {
        true
      }
    }

    Function("ignoringBatteryOptimizations") {
      (context.getSystemService(Context.POWER_SERVICE) as PowerManager).isIgnoringBatteryOptimizations(context.packageName)
    }

    // System dialog "Let app always run in background?"; if that fails: the app list
    Function("requestIgnoreBatteryOptimizations") {
      launch(Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:" + context.packageName))) ||
        launch(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
    }

    Function("setScreenSecure") { secure: Boolean ->
      ScreenGuard.set(context, appContext.currentActivity, secure)
    }

    Function("isBenchBuild") {
      ScreenGuard.isBenchBuild(context)
    }

    Function("openNotificationSettings") {
      val i = if (Build.VERSION.SDK_INT >= 26) {
        Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
      } else {
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + context.packageName))
      }
      launch(i)
    }
  }
}
