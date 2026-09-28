// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.wardenwatch

// "Like an incoming call" mode (off by default): a full-screen intent opens this screen over the
// lock screen and turns the screen on. It shows the same as the public version of the notification:
// host, risk, countdown; the command only with the "Show the command on the lock screen" option.
// The only buttons are "Open" (unlock, then the card and biometrics in the app) and "Later"
// (close the screen, the notification stays). There is no "Allow" here and there will not be: the
// screen is visible without unlocking. Request resolved or withdrawn: the screen closes; expired:
// "Expired, denied", then close.

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView

class IncomingActivity : Activity() {
  private var cardId: String? = null
  private val main = Handler(Looper.getMainLooper())
  private lateinit var title: TextView
  private lateinit var host: TextView
  private lateinit var risk: TextView
  private lateinit var left: TextView
  private lateinit var command: TextView
  private lateinit var buttons: LinearLayout
  private var closing = false

  private val ticker = object : Runnable {
    override fun run() {
      refresh()
    }
  }

  @Suppress("DEPRECATION")
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    if (Build.VERSION.SDK_INT >= 27) {
      setShowWhenLocked(true)
      setTurnScreenOn(true)
    } else {
      window.addFlags(WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON)
    }
    window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    ScreenGuard.apply(this) // FLAG_SECURE: no host, risk or command in screenshots and screen recording
    setContentView(layout())
    cardId = intent?.getStringExtra(EXTRA_ID)
    Notifier.attachIncoming(this)
    refresh()
  }

  override fun onNewIntent(intent: Intent) {
    super.onNewIntent(intent)
    setIntent(intent)
    cardId = intent.getStringExtra(EXTRA_ID)
    closing = false
    refresh()
  }

  override fun onDestroy() {
    main.removeCallbacksAndMessages(null)
    Notifier.attachIncoming(null)
    super.onDestroy()
  }

  /** Redraw from the current request state; called by Notifier (main thread) and the timer. */
  fun refresh() {
    main.removeCallbacks(ticker)
    if (closing) return
    val now = System.currentTimeMillis()
    val r = Notifier.request(cardId)
    if (r == null) {
      val at = Notifier.expiredAt(cardId)
      if (at == null) {
        finish()
        return
      }
      title.text = Notifier.text(this, "expiredTitle")
      left.text = ""
      buttons.visibility = View.GONE
      closing = true
      main.postDelayed({ finish() }, 3000)
      return
    }
    title.text = Notifier.text(this, "requestTitle")
    host.text = r.host
    risk.text = Notifier.riskLine(this, r)
    risk.setTextColor(if (r.danger) Color.rgb(0xF8, 0x71, 0x71) else Color.rgb(0xCB, 0xD5, 0xE1))
    left.text = if (r.expiresAt > 0) Notifier.left(r.expiresAt - now) else ""
    command.text = r.command ?: Notifier.text(this, "commandHidden")
    command.typeface = if (r.command != null) Typeface.MONOSPACE else Typeface.DEFAULT
    main.postDelayed(ticker, if (r.expiresAt > 0) Notifier.msToNextSecond(r.expiresAt, now) else 1000)
  }

  private fun openCard() {
    val id = cardId
    val go = {
      startActivity(Notifier.openAppIntent(this, if (id != null) Notifier.cardUri(id) else null))
      finish()
    }
    val km = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
    if (Build.VERSION.SDK_INT >= 26 && km.isKeyguardLocked) {
      // Unlock first (PIN, fingerprint), then the app: approval happens there, after biometrics
      km.requestDismissKeyguard(
        this,
        object : KeyguardManager.KeyguardDismissCallback() {
          override fun onDismissSucceeded() {
            go()
          }
        },
      )
    } else {
      go()
    }
  }

  private fun dp(v: Int): Int = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

  private fun label(size: Float, color: Int, bold: Boolean = false): TextView =
    TextView(this).apply {
      setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
      setTextColor(color)
      gravity = Gravity.CENTER
      if (bold) typeface = Typeface.DEFAULT_BOLD
      setPadding(0, dp(6), 0, dp(6))
    }

  private fun button(text: String, filled: Boolean, onClick: () -> Unit): Button =
    Button(this).apply {
      this.text = text
      setAllCaps(false)
      setTextSize(TypedValue.COMPLEX_UNIT_SP, 18f)
      setTextColor(if (filled) Color.WHITE else Color.rgb(0xE5, 0xE7, 0xEB))
      background = GradientDrawable().apply {
        cornerRadius = dp(28).toFloat()
        if (filled) setColor(Color.rgb(0x25, 0x63, 0xEB)) else setStroke(dp(2), Color.rgb(0x4B, 0x55, 0x63))
      }
      setOnClickListener { onClick() }
    }

  private fun layout(): View {
    val root = LinearLayout(this).apply {
      orientation = LinearLayout.VERTICAL
      gravity = Gravity.CENTER
      setBackgroundColor(Color.rgb(0x0E, 0x11, 0x17))
      setPadding(dp(28), dp(48), dp(28), dp(48))
    }
    val icon = ImageView(this).apply {
      setImageResource(R.drawable.ic_stat_wardenclaw)
      setColorFilter(Color.WHITE)
    }
    root.addView(icon, LinearLayout.LayoutParams(dp(56), dp(56)).apply { bottomMargin = dp(16) })
    title = label(26f, Color.WHITE, bold = true)
    host = label(22f, Color.WHITE)
    risk = label(18f, Color.rgb(0xCB, 0xD5, 0xE1))
    left = label(44f, Color.WHITE, bold = true).apply { typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD) }
    command = label(14f, Color.rgb(0x9C, 0xA3, 0xAF)).apply { maxLines = 6 }
    for (v in listOf(title, host, risk, left, command)) root.addView(v, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT))
    buttons = LinearLayout(this).apply {
      orientation = LinearLayout.HORIZONTAL
      gravity = Gravity.CENTER
    }
    val later = button(Notifier.text(this, "later"), false) { finish() }
    val open = button(Notifier.text(this, "open"), true) { openCard() }
    buttons.addView(later, LinearLayout.LayoutParams(0, dp(56), 1f).apply { rightMargin = dp(8) })
    buttons.addView(open, LinearLayout.LayoutParams(0, dp(56), 1f).apply { leftMargin = dp(8) })
    root.addView(buttons, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(32) })
    return root
  }

  companion object {
    const val EXTRA_ID = "com.wardenclaw.cardId"
  }
}
