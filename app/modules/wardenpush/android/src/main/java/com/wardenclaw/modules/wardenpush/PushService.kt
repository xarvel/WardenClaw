// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.wardenpush

// The relay's FCM data message (protocol/README.md section 8): sid, id, to, kind, exp, body, all
// strings. It is sent when a frame for this phone arrives and the phone has no live connection.
// The box is not opened here: the notification says "Approval request · Open to review" and
// nothing of the command, a tap opens the feed, the app connects, opens the box and shows the
// card. No actions on the notification: approving happens only in the app after the owner check.

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

class PushService : FirebaseMessagingService() {
  override fun onNewToken(token: String) {
    // the app registers the new token with the relay (phonePush.ts); not running: at its next start
    WardenPushModule.tokenChanged?.invoke()
  }

  override fun onMessageReceived(message: RemoteMessage) {
    val d = message.data
    val id = d["id"] ?: return
    if (d["kind"] != "card" || !FRAME_ID.matches(id)) return
    val exp = d["exp"]?.toLongOrNull() ?: return
    val left = exp - System.currentTimeMillis()
    if (left <= 0) return
    show(this, id, left)
  }

  companion object {
    private const val CHANNEL = "wc_push_requests_v1"
    private const val TAG = "wc.push"
    private val FRAME_ID = Regex("^[0-9a-f]{32}$")

    private fun manager(ctx: Context) = ctx.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

    private fun show(ctx: Context, frameId: String, leftMs: Long) {
      if (Build.VERSION.SDK_INT < 26) return // no channels: the background service's own notifications remain
      val nm = manager(ctx)
      nm.createNotificationChannel(
        NotificationChannel(CHANNEL, "Approval requests", NotificationManager.IMPORTANCE_HIGH).apply {
          description = "A request waits for your decision and the app is not connected"
          lockscreenVisibility = Notification.VISIBILITY_PUBLIC // the text names no host and no command
        }
      )
      val open = (ctx.packageManager.getLaunchIntentForPackage(ctx.packageName) ?: Intent()).apply {
        action = Intent.ACTION_VIEW
        data = Uri.parse("wardenclaw://feed")
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
      }
      val n = Notification.Builder(ctx, CHANNEL)
        .setSmallIcon(R.drawable.ic_stat_wardenpush)
        .setContentTitle("Approval request")
        .setContentText("Open to review")
        .setCategory(Notification.CATEGORY_MESSAGE)
        .setVisibility(Notification.VISIBILITY_PUBLIC)
        .setAutoCancel(true)
        .setTimeoutAfter(leftMs)
        .setContentIntent(PendingIntent.getActivity(ctx, 0, open, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE))
        .build()
      nm.notify(TAG, frameId.hashCode(), n)
    }

    /** The app is open: the cards are in the feed, the notifications are no longer needed. */
    fun clearAll(ctx: Context) {
      val nm = manager(ctx)
      for (sbn in nm.activeNotifications) if (sbn.tag == TAG) nm.cancel(sbn.tag, sbn.id)
    }
  }
}
