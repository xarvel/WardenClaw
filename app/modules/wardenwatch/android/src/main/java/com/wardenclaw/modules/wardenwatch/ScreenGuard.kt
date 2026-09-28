// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.wardenwatch

// Screen protection (FLAG_SECURE): screenshots, screen recording, the Recents preview and
// assistants that read the screen do not see agent commands. MainActivity sets the flag itself in
// onCreate (config plugin plugins/withAppHardening.js, same meta-data and SharedPreferences),
// IncomingActivity via apply(). Protection can be removed only in the bench build (meta-data
// com.wardenclaw.BENCH = true in the manifest), for documentation screenshots; in any other build
// set(false) does nothing.

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.view.WindowManager

object ScreenGuard {
  private const val PREFS = "wardenclaw.screen"
  private const val KEY_OFF = "protect_off"
  private const val BENCH_META = "com.wardenclaw.BENCH"

  fun isBenchBuild(ctx: Context): Boolean =
    try {
      @Suppress("DEPRECATION")
      ctx.packageManager.getApplicationInfo(ctx.packageName, PackageManager.GET_META_DATA).metaData?.getBoolean(BENCH_META, false) == true
    } catch (e: Exception) {
      false
    }

  /** Protection is turned off by the bench build switch; in any other build it is always on. */
  fun protectionOff(ctx: Context): Boolean =
    isBenchBuild(ctx) && ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY_OFF, false)

  fun apply(activity: Activity) {
    if (protectionOff(activity)) activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    else activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
  }

  /** false: not a bench build, protection cannot be removed (turning it on always works). */
  fun set(ctx: Context, activity: Activity?, secure: Boolean): Boolean {
    if (!secure && !isBenchBuild(ctx)) return false
    ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY_OFF, !secure).apply()
    activity?.runOnUiThread { apply(activity) }
    return true
  }
}
