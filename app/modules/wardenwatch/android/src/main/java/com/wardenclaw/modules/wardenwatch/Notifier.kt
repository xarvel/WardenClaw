// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.wardenwatch

// Local notifications without Firebase or a cloud. Channels:
//   wardenclaw.watch        persistent service notification (min importance, silent): real status
//   wardenclaw.requests.v2  approval requests: high importance, sound, vibration, heads-up
//   wardenclaw.missed.v2    expired requests ("Expired, denied"): silent but default importance,
//                           otherwise Pixel hides "silent" notifications from the lock screen
//   wardenclaw.status       "service did not start after reboot" or stopped after repeated
//                           background task failures: quiet
//
// Lock screen. Anyone holding the phone sees the command, so by default it is in neither the
// public nor the full version of the notification: VISIBILITY_PRIVATE hides the full version only
// if "Show sensitive content" is off in Android (on by default on Pixel), and the app cannot set
// the channel visibility (the system overwrites it when the channel is created).
// Public version: "Approval request · <host> · risk: <level> · M:SS left".
// The command gets into the notification only with the "Show the command on the lock screen"
// option. The notification has no actions: neither "Allow" nor "Deny". Tapping opens the card via
// unlock (the app activity is not showWhenLocked), then biometrics in the app.
//
// Lifecycle: each request gets its own notification in a group with a summary (GROUP_ALERT_CHILDREN:
// the new request sounds, the summary is silent). A resolved request is removed, an expired one is
// replaced by a silent "Expired, denied" in the missed channel. Countdown: chronometer in the
// header plus "M:SS left" text; the text updates once a second while the screen is on, at most 4
// notifications per second (Android drops updates beyond 5 per second).
//
// Texts come from JS in the UI language (configure) and are stored in SharedPreferences so that
// the service, restarted by the system without UI, shows them in the same language.

import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.media.AudioAttributes
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PowerManager
import android.provider.Settings
import android.text.format.DateFormat
import android.util.Log
import org.json.JSONObject
import java.lang.ref.WeakReference
import java.util.Date
import java.util.Locale

object Notifier {
  const val CH_SERVICE = "wardenclaw.watch"
  const val CH_REQUESTS = "wardenclaw.requests.v2"
  const val CH_MISSED = "wardenclaw.missed.v2"
  const val CH_STATUS = "wardenclaw.status"
  // v1 of the requests channel was created without vibration; after creation only the user changes
  // channel settings, hence a new id, and the old one is deleted
  private const val CH_REQUESTS_V1 = "wardenclaw.requests"
  // v1 of the expired channel had low importance: it is not visible on the lock screen
  private const val CH_MISSED_V1 = "wardenclaw.missed"
  const val ONGOING_ID = 7301
  private const val REQUEST_ID = 7302
  private const val SUMMARY_ID = 7303
  private const val PAUSED_ID = 7304
  private const val REQUEST_TAG = "wardenclaw.request:"
  private const val SUMMARY_TAG = "wardenclaw.summary"
  private const val GROUP = "wardenclaw.requests"
  private const val PREFS = "wardenclaw.watch"
  private const val TAG = "WardenWatch"
  /** Android drops notification updates beyond 5 per second per app. */
  private const val UPDATES_PER_SECOND = 4
  /** Fallback expiry if JS did not make it: slightly after the deadline (the server decides on its own). */
  private const val EXPIRY_GRACE_MS = 2000L

  private val defaults = mapOf(
    "serviceTitle" to "WardenClaw",
    "serviceText" to "Connecting to the server…",
    "requestTitle" to "Approval request",
    "requestLine" to "{host} · {risk} risk · {left} left",
    "requestLineNoExpiry" to "{host} · {risk} risk",
    "riskLine" to "risk: {risk}",
    "summaryTitle" to "Waiting for a decision: {n}",
    "summaryLine" to "{hosts} · next expires in {left}",
    "expiredTitle" to "Expired, denied",
    "expiredText" to "{host} · {time}",
    "commandHidden" to "The command is shown after you unlock the phone",
    "open" to "Open",
    "later" to "Later",
    "pausedTitle" to "Approval requests are paused",
    "pausedText" to "Open WardenClaw to receive requests again",
    "pausedCrashText" to "Background service stopped after repeated errors. Open WardenClaw.",
    "channelService" to "Background connection",
    "channelRequests" to "Approval requests",
    "channelMissed" to "Missed requests",
    "channelStatus" to "Connection problems",
  )

  /** A request in a notification: only what may be shown on the lock screen, plus the command by option. */
  data class Req(
    val id: String,
    val host: String,
    val risk: String, // ready-made word in the UI language: "high"
    val danger: Boolean,
    val createdAt: Long,
    val expiresAt: Long, // 0: no deadline
    val command: String?, // only with the "Show the command on the lock screen" option
    var fullScreen: Boolean = false,
    // The first post rang and popped up. Updates (countdown, risk) keep the same group behavior:
    // otherwise SystemUI treats the updated notification as "silent" and removes the heads-up at once.
    var alerting: Boolean = false,
  )

  private val main = Handler(Looper.getMainLooper())
  // Everything below changes only on the main thread
  private val pending = LinkedHashMap<String, Req>()
  private val expired = HashMap<String, Long>() // id → when it expired (for the "like a call" screen)
  private var appCtx: Context? = null
  private var screenReceiver: BroadcastReceiver? = null
  private var ticking = false
  private var incoming: WeakReference<IncomingActivity>? = null

  private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

  fun saveTexts(ctx: Context, texts: Map<String, String>) {
    val e = prefs(ctx).edit()
    for ((k, v) in texts) if (defaults.containsKey(k)) e.putString(k, v)
    e.apply()
  }

  fun text(ctx: Context, key: String): String = prefs(ctx).getString(key, null) ?: defaults[key] ?: key

  private fun manager(ctx: Context) = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

  private fun fill(tpl: String, vararg kv: Pair<String, String>): String {
    var s = tpl
    for ((k, v) in kv) s = s.replace("{$k}", v)
    return s
  }

  /** "1:40": minutes without a leading zero, two-digit seconds; rounded down like the header chronometer. */
  fun left(ms: Long): String {
    val s = (ms / 1000).coerceAtLeast(0)
    return String.format(Locale.ROOT, "%d:%02d", s / 60, s % 60)
  }

  /** How long until the next second change in the countdown: the text changes with the chronometer. */
  fun msToNextSecond(expiresAt: Long, now: Long): Long = Math.floorMod(expiresAt - now, 1000L) + 15

  /** "risk: high" for the "like a call" screen. */
  fun riskLine(ctx: Context, r: Req): String = fill(text(ctx, "riskLine"), "risk" to r.risk)

  fun ensureChannels(ctx: Context) {
    if (Build.VERSION.SDK_INT < 26) return
    val nm = manager(ctx)
    val svc = NotificationChannel(CH_SERVICE, text(ctx, "channelService"), NotificationManager.IMPORTANCE_MIN).apply {
      setShowBadge(false)
      enableVibration(false)
      setSound(null, null)
    }
    val req = NotificationChannel(CH_REQUESTS, text(ctx, "channelRequests"), NotificationManager.IMPORTANCE_HIGH).apply {
      enableVibration(true)
      vibrationPattern = longArrayOf(0, 300, 200, 300)
      enableLights(true)
      setSound(
        Settings.System.DEFAULT_NOTIFICATION_URI,
        AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_NOTIFICATION).setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build(),
      )
      // The system overwrites this when the app creates the channel (see the header); kept as intent
      lockscreenVisibility = Notification.VISIBILITY_PRIVATE
    }
    val missed = NotificationChannel(CH_MISSED, text(ctx, "channelMissed"), NotificationManager.IMPORTANCE_DEFAULT).apply {
      setShowBadge(true)
      setSound(null, null)
      enableVibration(false)
    }
    val status = NotificationChannel(CH_STATUS, text(ctx, "channelStatus"), NotificationManager.IMPORTANCE_LOW).apply {
      setShowBadge(false)
    }
    // A repeated call with the same id updates only the name (only the user changes importance)
    nm.createNotificationChannels(listOf(svc, req, missed, status))
    for (old in listOf(CH_REQUESTS_V1, CH_MISSED_V1)) if (nm.getNotificationChannel(old) != null) nm.deleteNotificationChannel(old)
  }

  @Suppress("DEPRECATION")
  private fun builder(ctx: Context, channel: String): Notification.Builder =
    if (Build.VERSION.SDK_INT >= 26) Notification.Builder(ctx, channel) else Notification.Builder(ctx)

  /** Open the app; uri (wardenclaw://feed?card=…) arrives in JS as a Linking url. */
  fun openAppIntent(ctx: Context, uri: String?): Intent {
    val intent = ctx.packageManager.getLaunchIntentForPackage(ctx.packageName) ?: Intent()
    if (uri != null) {
      intent.action = Intent.ACTION_VIEW
      intent.data = Uri.parse(uri)
    }
    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
    return intent
  }

  private fun openApp(ctx: Context, uri: String?, requestCode: Int): PendingIntent =
    PendingIntent.getActivity(ctx, requestCode, openAppIntent(ctx, uri), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

  fun cardUri(id: String) = "wardenclaw://feed?card=" + Uri.encode(id)

  // ---------------------------------------------------------------------------
  // Persistent service notification: JS writes the status (setStatus), until then "connecting"
  // ---------------------------------------------------------------------------

  @Suppress("DEPRECATION")
  fun ongoing(ctx: Context): Notification {
    val p = prefs(ctx)
    val b = builder(ctx, CH_SERVICE)
      .setSmallIcon(R.drawable.ic_stat_wardenclaw)
      .setContentTitle(p.getString("statusTitle", null) ?: text(ctx, "serviceTitle"))
      .setContentText(p.getString("statusText", null) ?: text(ctx, "serviceText"))
      .setOngoing(true)
      .setOnlyAlertOnce(true)
      .setShowWhen(false)
      .setCategory(Notification.CATEGORY_SERVICE)
      .setVisibility(Notification.VISIBILITY_PUBLIC) // connection status only, no requests
      .setContentIntent(openApp(ctx, null, 0))
    if (Build.VERSION.SDK_INT < 26) b.setPriority(Notification.PRIORITY_MIN)
    return b.build()
  }

  /** The service was just created: the previous status ("connected") is no longer true. */
  fun resetStatus(ctx: Context) {
    prefs(ctx).edit().remove("statusTitle").remove("statusText").apply()
  }

  fun setStatus(ctx: Context, title: String, text: String) {
    prefs(ctx).edit().putString("statusTitle", title).putString("statusText", text).apply()
    if (WatchService.running) refreshOngoing(ctx)
  }

  fun refreshOngoing(ctx: Context) {
    manager(ctx).notify(ONGOING_ID, ongoing(ctx))
  }

  /**
   * The service did not come up (after a reboot, an update or an Android refusal) or stopped after
   * repeated task failures (textKey "pausedCrashText"): say what to do. Tapping opens the app.
   */
  fun pausedNotice(ctx: Context, textKey: String = "pausedText") {
    ensureChannels(ctx)
    val body = text(ctx, textKey)
    val b = builder(ctx, CH_STATUS)
      .setSmallIcon(R.drawable.ic_stat_wardenclaw)
      .setContentTitle(text(ctx, "pausedTitle"))
      .setContentText(body)
      .setStyle(Notification.BigTextStyle().bigText(body)) // long text in full when expanded
      .setAutoCancel(true)
      .setVisibility(Notification.VISIBILITY_PUBLIC)
      .setContentIntent(openApp(ctx, null, 1))
    try {
      manager(ctx).notify(PAUSED_ID, b.build())
    } catch (e: Exception) {
      Log.w(TAG, "paused notice failed", e)
    }
  }

  fun clearPausedNotice(ctx: Context) {
    manager(ctx).cancel(PAUSED_ID)
  }

  // ---------------------------------------------------------------------------
  // Requests
  // ---------------------------------------------------------------------------

  /** Line without the command: "pi · risk: high · 1:40 left". The same one on the lock screen. */
  fun line(ctx: Context, r: Req, now: Long): String =
    if (r.expiresAt > 0) fill(text(ctx, "requestLine"), "host" to r.host, "risk" to r.risk, "left" to left(r.expiresAt - now))
    else fill(text(ctx, "requestLineNoExpiry"), "host" to r.host, "risk" to r.risk)

  private fun countdown(b: Notification.Builder, r: Req) {
    if (r.expiresAt > 0) {
      b.setWhen(r.expiresAt).setShowWhen(true).setUsesChronometer(true).setChronometerCountDown(true)
    } else {
      b.setWhen(r.createdAt).setShowWhen(true)
    }
  }

  @Suppress("DEPRECATION")
  private fun buildRequest(ctx: Context, r: Req, now: Long): Notification {
    val title = text(ctx, "requestTitle")
    val body = line(ctx, r, now)
    val pub = builder(ctx, CH_REQUESTS)
      .setSmallIcon(R.drawable.ic_stat_wardenclaw)
      .setContentTitle(title)
      .setContentText(body)
    countdown(pub, r)
    val b = builder(ctx, CH_REQUESTS)
      .setSmallIcon(R.drawable.ic_stat_wardenclaw)
      .setContentTitle(title)
      .setContentText(body)
      .setAutoCancel(true)
      .setOnlyAlertOnce(true) // updates (countdown, risk) do not ring again
      .setCategory(if (r.fullScreen) Notification.CATEGORY_CALL else Notification.CATEGORY_REMINDER)
      .setGroup(GROUP)
      .setPublicVersion(pub.build())
      .setContentIntent(openApp(ctx, cardUri(r.id), r.id.hashCode()))
    countdown(b, r)
    if (Build.VERSION.SDK_INT >= 26) {
      // Silent group child: a request the person has already seen in the open app
      b.setGroupAlertBehavior(if (r.alerting) Notification.GROUP_ALERT_CHILDREN else Notification.GROUP_ALERT_SUMMARY)
    } else if (r.alerting) {
      b.setPriority(Notification.PRIORITY_HIGH)
      b.setDefaults(Notification.DEFAULT_ALL)
    }
    if (r.command != null) {
      // The person turned the option on: the command is visible on the lock screen too
      b.setStyle(Notification.BigTextStyle().bigText(body + "\n" + r.command))
      b.setVisibility(Notification.VISIBILITY_PUBLIC)
    } else {
      b.setVisibility(Notification.VISIBILITY_PRIVATE)
    }
    if (r.fullScreen) b.setFullScreenIntent(incomingIntent(ctx, r.id), true)
    return b.build()
  }

  @Suppress("DEPRECATION")
  private fun postSummary(ctx: Context, now: Long) {
    val nm = manager(ctx)
    if (pending.size < 2) {
      nm.cancel(SUMMARY_TAG, SUMMARY_ID)
      return
    }
    val list = pending.values.sortedBy { if (it.expiresAt > 0) it.expiresAt else Long.MAX_VALUE }
    val first = list.first()
    val hosts = list.map { it.host }.distinct().joinToString(", ")
    val title = fill(text(ctx, "summaryTitle"), "n" to list.size.toString())
    val body = if (first.expiresAt > 0) fill(text(ctx, "summaryLine"), "hosts" to hosts, "left" to left(first.expiresAt - now)) else hosts
    val style = Notification.InboxStyle().setBigContentTitle(title)
    for (r in list.take(6)) style.addLine(line(ctx, r, now))
    val pub = builder(ctx, CH_REQUESTS)
      .setSmallIcon(R.drawable.ic_stat_wardenclaw)
      .setContentTitle(title)
      .setContentText(body)
    countdown(pub, first)
    val b = builder(ctx, CH_REQUESTS)
      .setSmallIcon(R.drawable.ic_stat_wardenclaw)
      .setContentTitle(title)
      .setContentText(body)
      .setStyle(style) // lines without commands: safe
      .setNumber(list.size)
      .setGroup(GROUP)
      .setGroupSummary(true)
      .setOnlyAlertOnce(true)
      .setAutoCancel(true)
      .setCategory(Notification.CATEGORY_REMINDER)
      .setVisibility(Notification.VISIBILITY_PRIVATE)
      .setPublicVersion(pub.build())
      .setContentIntent(openApp(ctx, "wardenclaw://feed", 2))
    countdown(b, first)
    if (Build.VERSION.SDK_INT >= 26) b.setGroupAlertBehavior(Notification.GROUP_ALERT_CHILDREN)
    nm.notify(SUMMARY_TAG, SUMMARY_ID, b.build())
  }

  /** Silent "Expired, denied · pi · 21:32" in place of the request notification (same tag). */
  private fun postExpired(ctx: Context, r: Req, at: Long) {
    val body = fill(text(ctx, "expiredText"), "host" to r.host, "time" to DateFormat.getTimeFormat(ctx).format(Date(at)))
    val b = builder(ctx, CH_MISSED)
      .setSmallIcon(R.drawable.ic_stat_wardenclaw)
      .setContentTitle(text(ctx, "expiredTitle"))
      .setContentText(body)
      .setWhen(at)
      .setShowWhen(true)
      .setAutoCancel(true)
      .setOnlyAlertOnce(true)
      .setCategory(Notification.CATEGORY_STATUS)
      .setVisibility(Notification.VISIBILITY_PUBLIC) // no command
      .setContentIntent(openApp(ctx, "wardenclaw://feed?missed=1", r.id.hashCode()))
    manager(ctx).notify(REQUEST_TAG + r.id, REQUEST_ID, b.build())
  }

  /**
   * Request state from JS: {pending:[{id, host, risk, danger, createdAt, expiresAt, command?, alert}],
   * expired:[{id, host, at}], fullScreen}. New ones from pending are shown (alert: with sound and
   * pop-up), known ones are updated silently, ones gone without an entry in expired are removed.
   */
  fun update(ctx: Context, json: String) {
    val app = ctx.applicationContext
    main.post {
      try {
        applyUpdate(app, JSONObject(json))
      } catch (e: Exception) {
        Log.w(TAG, "update failed", e)
      }
    }
  }

  private fun applyUpdate(ctx: Context, o: JSONObject) {
    appCtx = ctx
    val nm = manager(ctx)
    val now = System.currentTimeMillis()
    val fullScreen = o.optBoolean("fullScreen", false) && canUseFullScreenIntent(ctx)
    val exp = o.optJSONArray("expired")
    if (exp != null) {
      for (i in 0 until exp.length()) {
        val x = exp.getJSONObject(i)
        val id = x.getString("id")
        val at = x.optLong("at", now)
        val r = pending.remove(id) ?: Req(id, x.optString("host", "?"), "", false, at, 0, null)
        expired[id] = at
        postExpired(ctx, r, at)
      }
    }
    val incomingList = LinkedHashMap<String, Pair<Req, Boolean>>()
    val arr = o.optJSONArray("pending")
    if (arr != null) {
      for (i in 0 until arr.length()) {
        val x = arr.getJSONObject(i)
        val r = Req(
          id = x.getString("id"),
          host = x.optString("host", "?"),
          risk = x.optString("risk", ""),
          danger = x.optBoolean("danger", false),
          createdAt = x.optLong("createdAt", now),
          expiresAt = x.optLong("expiresAt", 0L),
          command = if (x.has("command") && !x.isNull("command")) x.getString("command") else null,
        )
        incomingList[r.id] = r to x.optBoolean("alert", false)
      }
    }
    // Resolved (by another device, in the app) and withdrawn: remove their notifications
    for (id in pending.keys.toList()) {
      if (incomingList.containsKey(id)) continue
      pending.remove(id)
      nm.cancel(REQUEST_TAG + id, REQUEST_ID)
    }
    var woke = false
    for ((id, pair) in incomingList) {
      val (r, alert) = pair
      val old = pending[id]
      if (old != null) {
        r.fullScreen = old.fullScreen
        r.alerting = old.alerting
        pending[id] = r
        if (old.risk != r.risk || old.command != r.command || old.expiresAt != r.expiresAt || old.host != r.host) {
          nm.notify(REQUEST_TAG + id, REQUEST_ID, buildRequest(ctx, r, now))
        }
        continue
      }
      r.fullScreen = alert && fullScreen
      r.alerting = alert
      pending[id] = r
      expired.remove(id)
      nm.notify(REQUEST_TAG + id, REQUEST_ID, buildRequest(ctx, r, now))
      if (alert && !r.fullScreen && !woke) {
        wakeScreen(ctx)
        woke = true
      }
    }
    postSummary(ctx, now)
    incoming?.get()?.refresh()
    scheduleTicks(ctx)
  }

  /** Remove all request notifications (the app is open: the cards are visible in the feed). */
  fun cancelAll(ctx: Context) {
    val app = ctx.applicationContext
    main.post {
      pending.clear()
      expired.clear()
      val nm = manager(app)
      for (sbn in nm.activeNotifications) {
        val tag = sbn.tag ?: continue
        if (tag.startsWith(REQUEST_TAG) || tag == SUMMARY_TAG) nm.cancel(tag, sbn.id)
      }
      incoming?.get()?.finish()
      stopTicks(app)
    }
  }

  /** For the "like a call" screen: the request, if it is still waiting. */
  fun request(id: String?): Req? = if (id == null) null else pending[id]

  fun expiredAt(id: String?): Long? = if (id == null) null else expired[id]

  fun attachIncoming(a: IncomingActivity?) {
    incoming = if (a == null) null else WeakReference(a)
  }

  // ---------------------------------------------------------------------------
  // Countdown in the text: once a second while the screen is on
  // ---------------------------------------------------------------------------

  private val tick = object : Runnable {
    override fun run() {
      ticking = false
      val ctx = appCtx ?: return
      if (pending.isEmpty()) return
      val now = System.currentTimeMillis()
      val nm = manager(ctx)
      // Fallback path: the deadline passed and JS is silent (the process sleeps without network).
      // The server has decided on its own: deny.
      for (r in pending.values.toList()) {
        if (r.expiresAt > 0 && now >= r.expiresAt + EXPIRY_GRACE_MS) {
          pending.remove(r.id)
          expired[r.id] = r.expiresAt
          postExpired(ctx, r, r.expiresAt)
        }
      }
      if (!interactive(ctx)) {
        // Screen is off: nobody sees the text. ACTION_SCREEN_ON wakes us, expiry is checked later.
        postSummary(ctx, now)
        incoming?.get()?.refresh()
        val nextExpiry = pending.values.filter { it.expiresAt > 0 }.minOfOrNull { it.expiresAt + EXPIRY_GRACE_MS - now }
        if (nextExpiry != null) {
          ticking = true
          main.postDelayed(this, nextExpiry.coerceAtLeast(1000))
        }
        return
      }
      for (r in pending.values) nm.notify(REQUEST_TAG + r.id, REQUEST_ID, buildRequest(ctx, r, now))
      postSummary(ctx, now)
      incoming?.get()?.refresh()
      if (pending.isEmpty()) return
      ticking = true
      main.postDelayed(this, nextTickDelay(System.currentTimeMillis()))
    }
  }

  /**
   * Next tick right after the second changes for the nearest deadline; less often with many
   * requests (update limit).
   */
  private fun nextTickDelay(now: Long): Long {
    val n = pending.size + if (pending.size >= 2) 1 else 0
    val period = 1000L * ((n + UPDATES_PER_SECOND - 1) / UPDATES_PER_SECOND).coerceAtLeast(1)
    val first = pending.values.filter { it.expiresAt > 0 }.minOfOrNull { it.expiresAt } ?: return period
    return period - 1000 + msToNextSecond(first, now)
  }

  private fun interactive(ctx: Context) = (ctx.getSystemService(Context.POWER_SERVICE) as PowerManager).isInteractive

  private fun scheduleTicks(ctx: Context) {
    if (pending.isEmpty()) {
      stopTicks(ctx)
      return
    }
    if (screenReceiver == null) {
      val r = object : BroadcastReceiver() {
        override fun onReceive(c: Context, i: Intent) {
          main.removeCallbacks(tick)
          ticking = false
          tick.run()
        }
      }
      val f = IntentFilter(Intent.ACTION_SCREEN_ON)
      try {
        if (Build.VERSION.SDK_INT >= 33) ctx.registerReceiver(r, f, Context.RECEIVER_NOT_EXPORTED) else ctx.registerReceiver(r, f)
        screenReceiver = r
      } catch (e: Exception) {
        Log.w(TAG, "screen receiver failed", e)
      }
    }
    if (!ticking) {
      ticking = true
      main.postDelayed(tick, nextTickDelay(System.currentTimeMillis()))
    }
  }

  private fun stopTicks(ctx: Context) {
    main.removeCallbacks(tick)
    ticking = false
    val r = screenReceiver ?: return
    screenReceiver = null
    try {
      ctx.unregisterReceiver(r)
    } catch (_: Exception) {
    }
  }

  // ---------------------------------------------------------------------------
  // Screen: wake-up, "like an incoming call" mode (full-screen intent)
  // ---------------------------------------------------------------------------

  /** Turn the screen on for a few seconds so that the request is visible on the lock screen. */
  @Suppress("DEPRECATION")
  private fun wakeScreen(ctx: Context) {
    val pm = ctx.getSystemService(Context.POWER_SERVICE) as PowerManager
    if (pm.isInteractive) return
    try {
      pm.newWakeLock(PowerManager.SCREEN_BRIGHT_WAKE_LOCK or PowerManager.ACQUIRE_CAUSES_WAKEUP or PowerManager.ON_AFTER_RELEASE, "WardenClaw:request")
        .acquire(5000)
    } catch (e: Exception) {
      Log.w(TAG, "wake failed", e)
    }
  }

  private fun incomingIntent(ctx: Context, id: String): PendingIntent {
    val i = Intent(ctx, IncomingActivity::class.java)
      .putExtra(IncomingActivity.EXTRA_ID, id)
      .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_USER_ACTION)
    return PendingIntent.getActivity(ctx, id.hashCode() xor 0x5a5a5a, i, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
  }

  /** Android 14+: the user grants the full-screen intent permission (Play revokes it from non-call apps). */
  fun canUseFullScreenIntent(ctx: Context): Boolean =
    if (Build.VERSION.SDK_INT >= 34) manager(ctx).canUseFullScreenIntent() else true

  fun enabled(ctx: Context): Boolean = manager(ctx).areNotificationsEnabled()

  /** Whether the requests channel is on (the user may have turned off just that channel). */
  fun requestsChannelEnabled(ctx: Context): Boolean {
    if (Build.VERSION.SDK_INT < 26) return true
    val ch = manager(ctx).getNotificationChannel(CH_REQUESTS) ?: return true
    return ch.importance != NotificationManager.IMPORTANCE_NONE
  }

  fun keyguardLocked(ctx: Context): Boolean = (ctx.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isKeyguardLocked
}
