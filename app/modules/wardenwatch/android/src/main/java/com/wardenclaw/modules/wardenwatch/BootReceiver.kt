// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.wardenwatch

// Brings the background service up after a phone reboot (BOOT_COMPLETED: after the first unlock,
// when keys and settings are available) and after an app update (MY_PACKAGE_REPLACED). Both
// events are among the Android 12+ exemptions for starting a foreground service from the
// background. The service comes up only if it was running before (the "wanted" flag is set by
// WatchService.start/stop). If that fails: a regular notification "Open WardenClaw to receive
// requests again".

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

class BootReceiver : BroadcastReceiver() {
  override fun onReceive(context: Context, intent: Intent) {
    val action = intent.action ?: return
    if (action != Intent.ACTION_BOOT_COMPLETED && action != Intent.ACTION_MY_PACKAGE_REPLACED) return
    if (!WatchService.wanted(context)) return
    Log.i("WardenWatch", "$action: starting the service")
    Notifier.ensureChannels(context)
    if (!WatchService.start(context)) Notifier.pausedNotice(context)
  }
}
