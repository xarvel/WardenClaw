// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.wardenwatch

// Foreground service of type specialUse: while the app is in the background, it keeps the JS task
// "WardenWatch" running (HeadlessJsTaskContext). While the task is active, RN does not pause JS
// timers, and the long-poll to wardend (/v1/pending) keeps working in the same JS context as the UI.
//
// Why specialUse and not dataSync: since targetSdk 35 dataSync is limited to 6 hours a day
// (Service.onTimeout), and the service must live permanently. specialUse requires
// FOREGROUND_SERVICE_SPECIAL_USE and <property PROPERTY_SPECIAL_USE_FGS_SUBTYPE> in the manifest
// (added by plugin/withWardenWatch.js). Android 12+ does not allow starting the service from the
// background, so it starts from the UI, after a reboot and after an app update (BootReceiver: these
// events are exempt); START_STICKY makes the system restart it. The "service wanted" flag lives in
// SharedPreferences: start() sets it, stop() clears it, BootReceiver decides by it.
// No wake lock: the long-poll wakes the CPU with incoming data, battery matters more.
//
// Crash loop protection: the JS task does not finish while the service is alive, so its end
// without stop() counts as a failure. A single failure: restart in 5 s. Three failures in 30 s
// (broken DB, bootstrap error): the service stops retrying, stops itself and asks to open the app.
// A task that ran longer than 60 s and a new service start from the app reset the count.
// The "wanted" flag is not cleared: after a reboot BootReceiver tries again, with the same limit.

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import com.facebook.react.ReactApplication
import com.facebook.react.ReactInstanceEventListener
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReactContext
import com.facebook.react.bridge.UiThreadUtil
import com.facebook.react.jstasks.HeadlessJsTaskConfig
import com.facebook.react.jstasks.HeadlessJsTaskContext
import com.facebook.react.jstasks.HeadlessJsTaskEventListener

class WatchService : Service(), HeadlessJsTaskEventListener {
  private var taskId: Int? = null
  private var taskContext: ReactContext? = null
  private val main = Handler(Looper.getMainLooper())
  // Everything below changes only on the main thread (onStartCommand, task listener, main)
  private var taskStartedAt = 0L // SystemClock.elapsedRealtime() of the current task start
  private val crashes = ArrayList<Long>() // when the task finished without stop(), over the last 30 s

  override fun onBind(intent: Intent?): IBinder? = null

  override fun onCreate() {
    super.onCreate()
    // The "connected" status from the previous run is no longer true: until JS answers, show "connecting"
    Notifier.resetStatus(this)
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    try {
      Notifier.ensureChannels(this)
      val n = Notifier.ongoing(this)
      if (Build.VERSION.SDK_INT >= 34) {
        startForeground(Notifier.ONGOING_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
      } else {
        startForeground(Notifier.ONGOING_ID, n)
      }
    } catch (e: Exception) {
      Log.w(TAG, "startForeground failed", e)
      running = false
      Notifier.pausedNotice(this)
      stopSelf()
      return START_NOT_STICKY
    }
    running = true
    Notifier.clearPausedNotice(this)
    // A start from the app (start(): called by the UI and BootReceiver) restarts the failure count.
    // A system restart via START_STICKY comes with intent == null and leaves the count alone.
    if (intent != null) crashes.clear()
    startJsTask()
    return START_STICKY
  }

  private fun startJsTask() {
    if (taskId != null || !running) return
    val app = application as? ReactApplication ?: return
    val host = app.reactHost ?: return
    val ctx = host.currentReactContext
    if (ctx != null) {
      runTask(ctx)
      return
    }
    host.addReactInstanceEventListener(
      object : ReactInstanceEventListener {
        override fun onReactContextInitialized(context: ReactContext) {
          host.removeReactInstanceEventListener(this)
          runTask(context)
        }
      },
    )
    host.start()
  }

  private fun runTask(ctx: ReactContext) {
    UiThreadUtil.runOnUiThread {
      if (taskId != null || !running) return@runOnUiThread
      try {
        val hc = HeadlessJsTaskContext.getInstance(ctx)
        hc.addTaskEventListener(this)
        taskContext = ctx
        taskId = hc.startTask(HeadlessJsTaskConfig(TASK_KEY, Arguments.createMap(), 0, true))
        taskStartedAt = SystemClock.elapsedRealtime()
      } catch (e: Exception) {
        Log.w(TAG, "headless task start failed", e)
      }
    }
  }

  override fun onHeadlessJsTaskStart(taskId: Int) = Unit

  override fun onHeadlessJsTaskFinish(taskId: Int) {
    if (taskId != this.taskId) return
    this.taskId = null
    // stop() clears running before JS finishes the task: this is a normal end
    if (!running) return
    // The JS task finished while the service must live: a failure. A long run before it resets the count.
    val now = SystemClock.elapsedRealtime()
    if (now - taskStartedAt > HEALTHY_RUN_MS) crashes.clear()
    crashes.removeAll { now - it > CRASH_WINDOW_MS }
    crashes.add(now)
    if (crashes.size >= MAX_CRASHES) {
      Log.w(TAG, "headless task failed ${crashes.size} times in ${CRASH_WINDOW_MS / 1000} s, stopping the service")
      giveUp()
      return
    }
    main.postDelayed({ startJsTask() }, RESTART_DELAY_MS)
  }

  /** The task fails again and again: do not restart, stop and ask to open the app. */
  private fun giveUp() {
    running = false
    main.removeCallbacksAndMessages(null)
    Notifier.pausedNotice(this, "pausedCrashText")
    stopSelf()
  }

  override fun onDestroy() {
    running = false
    main.removeCallbacksAndMessages(null)
    val id = taskId
    val ctx = taskContext
    taskId = null
    taskContext = null
    if (ctx != null) {
      val hc = HeadlessJsTaskContext.getInstance(ctx)
      hc.removeTaskEventListener(this)
      if (id != null && hc.isTaskRunning(id)) hc.finishTask(id)
    }
    super.onDestroy()
  }

  companion object {
    const val TASK_KEY = "WardenWatch"
    private const val TAG = "WardenWatch"

    private const val PREFS = "wardenclaw.watch"
    private const val WANTED = "serviceWanted"

    private const val RESTART_DELAY_MS = 5_000L
    /** This many task failures within CRASH_WINDOW_MS: a loop, the service stops. */
    private const val MAX_CRASHES = 3
    private const val CRASH_WINDOW_MS = 30_000L
    /** A task that ran longer was healthy: earlier failures do not count. */
    private const val HEALTHY_RUN_MS = 60_000L

    @Volatile
    var running = false

    /** The service should run (the user turned it on, a server is paired): BootReceiver decides. */
    fun wanted(ctx: Context): Boolean = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(WANTED, false)

    private fun setWanted(ctx: Context, on: Boolean) {
      ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(WANTED, on).apply()
    }

    fun start(ctx: Context): Boolean {
      setWanted(ctx, true)
      return try {
        val i = Intent(ctx, WatchService::class.java)
        if (Build.VERSION.SDK_INT >= 26) ctx.startForegroundService(i) else ctx.startService(i)
        true
      } catch (e: Exception) {
        // ForegroundServiceStartNotAllowedException: background start is forbidden (Android 12+)
        Log.w(TAG, "start failed", e)
        false
      }
    }

    fun stop(ctx: Context) {
      setWanted(ctx, false)
      running = false
      ctx.stopService(Intent(ctx, WatchService::class.java))
    }
  }
}
