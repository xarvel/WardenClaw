// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.wardenpush

// JS API of push notifications on Android (FCM), the surface of the iOS module where it applies:
//   available()                 this build has a Firebase configuration (google-services.json)
//   getPermission()             → {status, timeSensitive, lockScreen, alert}
//   requestPermission()         POST_NOTIFICATIONS dialog on Android 13+ → the same shape
//   register()                  → {token, environment: "production", topic: <package name>}
//   takeLaunchCardId()          always null: a tap arrives in JS as the link wardenclaw://feed
//   clearDelivered(cardId)      removes the push notifications (they name no card: all of them)
//   event onToken               Firebase issued a new token: register again
// The message itself is handled in PushService.

import android.Manifest
import android.app.NotificationManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging
import expo.modules.interfaces.permissions.PermissionsResponseListener
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class WardenPushModule : Module() {
  private val context: Context
    get() = appContext.reactContext?.applicationContext ?: throw IllegalStateException("React context is not available")

  private fun prefs() = context.getSharedPreferences("wardenclaw.push", Context.MODE_PRIVATE)

  private fun permission(): Map<String, Any> {
    val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    val runtime = Build.VERSION.SDK_INT < 33 || context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    val status = when {
      runtime && nm.areNotificationsEnabled() -> "granted"
      // Android does not tell "never asked" from "denied": the dialog was shown once we asked
      !runtime && !prefs().getBoolean("asked", false) -> "notDetermined"
      else -> "denied"
    }
    return mapOf("status" to status, "timeSensitive" to "notSupported", "lockScreen" to "unknown", "alert" to "unknown")
  }

  override fun definition() = ModuleDefinition {
    Name("WardenPush")

    Events("onToken")

    OnCreate {
      tokenChanged = { sendEvent("onToken", mapOf<String, Any?>()) }
    }

    OnDestroy {
      tokenChanged = null
    }

    Function("available") {
      FirebaseApp.getApps(context).isNotEmpty()
    }

    Function("getPermission") {
      permission()
    }

    AsyncFunction("requestPermission") { promise: Promise ->
      val permissions = appContext.permissions
      if (Build.VERSION.SDK_INT < 33 || permissions == null) {
        promise.resolve(permission())
        return@AsyncFunction
      }
      prefs().edit().putBoolean("asked", true).apply()
      permissions.askForPermissions(PermissionsResponseListener { promise.resolve(permission()) }, Manifest.permission.POST_NOTIFICATIONS)
    }

    AsyncFunction("register") { promise: Promise ->
      val ctx = context
      if (FirebaseApp.getApps(ctx).isEmpty()) {
        promise.reject(CodedException("NO_FIREBASE", "This build has no Firebase configuration", null))
        return@AsyncFunction
      }
      FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
        val token = if (task.isSuccessful) task.result else null
        if (token.isNullOrEmpty()) {
          promise.reject(CodedException("NO_TOKEN", task.exception?.message ?: "Firebase gave no token", task.exception))
        } else {
          promise.resolve(mapOf("token" to token, "environment" to "production", "topic" to ctx.packageName))
        }
      }
    }

    Function("takeLaunchCardId") {
      null as String?
    }

    Function("clearDelivered") { _: String? ->
      PushService.clearAll(context)
    }
  }

  companion object {
    /** Set while the module lives: PushService.onNewToken calls it. */
    @Volatile
    var tokenChanged: (() -> Unit)? = null
  }
}
