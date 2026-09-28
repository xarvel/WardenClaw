// SPDX-License-Identifier: GPL-3.0-or-later
package com.wardenclaw.modules.yubikey

// YubiKey over NFC or USB-C through Yubico's official yubikit-android library: raw CTAP2 (FIDO2)
// without a browser and without Credential Manager; clientDataHash comes from JS (the app builds it,
// binding it to the wardend ticket, see protocol/HARDWARE.md), the key signs
// authenticatorData || clientDataHash.
//
//   register(rpId, userId, userName, clientDataHash, pin?)      → {credentialId, attestationObject, alg}
//   getAssertion(rpId, clientDataHash, credentialId, pin?)      → {credentialId, authenticatorData, signature, signCount}
//   cancel()                                                     → stop waiting for a tap
//
// All bytes are base64url without padding. The tap wait is up to 45 s (the wardend ticket ts window is 60 s); if the tag
// drops mid-exchange (TagLost/IOException), we wait for the next tap instead of failing.
//
// Transports: NFC (hold to the back panel) and USB (plug into USB-C) are listened to at once, the
// operation runs over whichever comes first. Over USB: we ask for the device permission ourselves
// (the system dialog), CTAP2 goes over HID (FidoConnection), or over CCID when HID is missing.
// Over USB the key waits for a touch of its contact (it blinks): JS learns this from the onStatus event
// {transport: "usb", state: "connected" | "permission" | "touch" | "removed" | "permission-denied"}.

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.hardware.usb.UsbManager
import android.nfc.NfcAdapter
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Base64
import android.util.Log
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.core.fido.FidoConnection
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.smartcard.SmartCardConnection
import com.yubico.yubikit.fido.Cbor
import com.yubico.yubikit.fido.ctap.ClientPin
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2
import com.yubico.yubikit.fido.webauthn.AuthenticatorData
import expo.modules.kotlin.Promise
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.IOException
import java.nio.ByteBuffer

private const val TOUCH_TIMEOUT_MS = 45_000L
private const val TAG = "WardenYubikey"

// COSE: EdDSA (Ed25519) preferred, ES256 as the fallback (wardend accepts both).
private const val ALG_EDDSA = -8
private const val ALG_ES256 = -7

class YubikeyException(code: String, message: String, cause: Throwable? = null) : CodedException(code, message, cause)

class YubikeyModule : Module() {
  private val main = Handler(Looper.getMainLooper())
  private var manager: YubiKitManager? = null
  private var activity: Activity? = null
  private var pending: Promise? = null
  private var timeout: Runnable? = null
  private var state: CommandState? = null
  private var busy = false // an exchange with a specific key is running (NFC or USB), the other transport waits
  private var nfcOn = false
  private var usbOn = false
  private var permReceiver: BroadcastReceiver? = null
  private val lock = Any()

  override fun definition() = ModuleDefinition {
    Name("Yubikey")

    Events("onStatus")

    // At least one transport exists: an NFC module or USB host (USB-C OTG).
    Function("isSupported") {
      val ctx = appContext.reactContext ?: return@Function false
      NfcAdapter.getDefaultAdapter(ctx) != null || hasUsbHost(ctx)
    }

    Function("hasNfc") {
      val ctx = appContext.reactContext ?: return@Function false
      NfcAdapter.getDefaultAdapter(ctx) != null
    }

    Function("hasUsb") {
      val ctx = appContext.reactContext ?: return@Function false
      hasUsbHost(ctx)
    }

    Function("isNfcEnabled") {
      val ctx = appContext.reactContext ?: return@Function false
      NfcAdapter.getDefaultAdapter(ctx)?.isEnabled == true
    }

    AsyncFunction("register") { rpId: String, userId: String, userName: String, clientDataHash: String, pin: String?, promise: Promise ->
      val cdh = unb64(clientDataHash)
      withKey(promise) { session, cmd ->
        val (pinParam, pinProto) = pinAuth(session, pin, ClientPin.PIN_PERMISSION_MC, rpId, cdh)
        val cred = session.makeCredential(
          cdh,
          mapOf("id" to rpId, "name" to "WardenClaw"),
          mapOf("id" to unb64(userId), "name" to userName, "displayName" to userName),
          listOf(
            mapOf("type" to "public-key", "alg" to ALG_EDDSA),
            mapOf("type" to "public-key", "alg" to ALG_ES256),
          ),
          null,
          null,
          mapOf("rk" to false),
          pinParam,
          pinProto,
          null,
          cmd,
        )
        // attestationObject is assembled here from the RAW authData: the packed attestation signature
        // covers the original bytes, re-serializing the COSE key would break its check in wardend.
        val raw = cred.authenticatorData
        val att = Cbor.encode(mapOf("fmt" to cred.format, "authData" to raw, "attStmt" to cred.attestationStatement))
        val parsed = AuthenticatorData.parseFrom(ByteBuffer.wrap(raw))
        val acd = parsed.attestedCredentialData ?: throw YubikeyException("BAD_RESPONSE", "no attested credential data in the key response")
        val alg = (acd.cosePublicKey[3] as? Number)?.toInt() ?: 0
        mapOf("credentialId" to b64(acd.credentialId), "attestationObject" to b64(att), "alg" to alg)
      }
    }

    AsyncFunction("getAssertion") { rpId: String, clientDataHash: String, credentialId: String, pin: String?, promise: Promise ->
      val cdh = unb64(clientDataHash)
      val credId = unb64(credentialId)
      withKey(promise) { session, cmd ->
        val (pinParam, pinProto) = pinAuth(session, pin, ClientPin.PIN_PERMISSION_GA, rpId, cdh)
        val list = session.getAssertions(
          rpId,
          cdh,
          listOf(mapOf("type" to "public-key", "id" to credId)),
          null,
          mapOf("up" to true),
          pinParam,
          pinProto,
          cmd,
        )
        val a = list.firstOrNull() ?: throw YubikeyException("NO_CREDENTIALS", "the key returned no signature")
        // with a single-id allowList the key may leave the credential out of the response
        val id = (a.credential?.get("id") as? ByteArray) ?: credId
        val ad = a.authenticatorData
        val count = AuthenticatorData.parseFrom(ByteBuffer.wrap(ad)).signCount
        mapOf("credentialId" to b64(id), "authenticatorData" to b64(ad), "signature" to b64(a.signature), "signCount" to count)
      }
    }

    AsyncFunction("cancel") {
      finish(null, YubikeyException("CANCELLED", "cancelled"))
    }

    OnActivityEntersBackground {
      finish(null, YubikeyException("CANCELLED", "the app went to the background"))
    }

    OnDestroy {
      finish(null, YubikeyException("CANCELLED", "the module was unloaded"))
    }
  }

  /** PIN → pinUvAuthParam over clientDataHash (the UV flag in the key's response). Without a PIN: (null, null). */
  private fun pinAuth(session: Ctap2Session, pin: String?, permission: Int, rpId: String, cdh: ByteArray): Pair<ByteArray?, Int?> {
    if (pin.isNullOrEmpty()) return Pair(null, null)
    val info = session.cachedInfo
    if (!ClientPin.isSupported(info)) throw YubikeyException("PIN_NOT_SUPPORTED", "the key does not support a PIN")
    val proto: PinUvAuthProtocol = if (info.pinUvAuthProtocols.contains(2)) PinUvAuthProtocolV2() else PinUvAuthProtocolV1()
    val cp = ClientPin(session, proto)
    val token = cp.getPinToken(pin.toCharArray(), permission, rpId)
    return Pair(proto.authenticate(token, cdh), proto.version)
  }

  private fun hasUsbHost(ctx: Context): Boolean = ctx.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST)

  private fun emit(transport: String, st: String) {
    try {
      sendEvent("onStatus", mapOf("transport" to transport, "state" to st))
    } catch (_: Exception) {
    }
  }

  private fun withKey(promise: Promise, op: (Ctap2Session, CommandState) -> Map<String, Any?>) {
    val act = appContext.currentActivity
    if (act == null) {
      promise.reject(YubikeyException("NO_ACTIVITY", "no active screen for NFC"))
      return
    }
    val ctx = act.applicationContext
    val nfc = NfcAdapter.getDefaultAdapter(ctx)
    val usb = hasUsbHost(ctx)
    if (nfc == null && !usb) {
      promise.reject(YubikeyException("NFC_UNAVAILABLE", "this phone has neither NFC nor USB host"))
      return
    }
    synchronized(lock) {
      if (pending != null) {
        promise.reject(YubikeyException("BUSY", "already waiting for a key tap"))
        return
      }
      pending = promise
      activity = act
      busy = false
      state = object : CommandState() {
        override fun onKeepAliveStatus(status: Byte) {
          if (status == CommandState.STATUS_UPNEEDED) emit("usb", "touch")
        }
      }
    }
    val mgr = manager ?: YubiKitManager(ctx).also { manager = it }
    main.post {
      if (synchronized(lock) { pending == null }) return@post
      var nfcError: YubikeyException? = null
      if (nfc != null) {
        try {
          mgr.startNfcDiscovery(NfcConfiguration().timeout(15_000), act) { device: NfcYubiKeyDevice -> runOn(device, "nfc", op) }
          nfcOn = true
        } catch (e: NfcNotAvailable) {
          nfcError = YubikeyException(if (e.isDisabled) "NFC_DISABLED" else "NFC_UNAVAILABLE", if (e.isDisabled) "NFC is off in settings" else "this phone has no NFC")
        }
      }
      if (usb) {
        try {
          // We ask for the USB device permission ourselves (onUsb): this way JS sees a refusal instead of waiting for the timeout.
          mgr.startUsbDiscovery(UsbConfiguration().handlePermissions(false)) { device: UsbYubiKeyDevice -> onUsb(ctx, device, op) }
          usbOn = true
          Log.i(TAG, "usb discovery started")
        } catch (e: Exception) {
          Log.w(TAG, "usb discovery failed", e)
        }
      }
      // No transport started: report the NFC reason (there is no USB, or it did not come up).
      if (!nfcOn && !usbOn) finish(null, nfcError ?: YubikeyException("NFC_UNAVAILABLE", "no NFC and no USB host"))
    }
    val t = Runnable { finish(null, YubikeyException("TIMEOUT", "the key was not tapped within ${TOUCH_TIMEOUT_MS / 1000} s")) }
    timeout = t
    main.postDelayed(t, TOUCH_TIMEOUT_MS)
  }

  /** USB: the key is plugged in. No permission: the system dialog, then by the answer either the exchange or an error. */
  private fun onUsb(ctx: Context, device: UsbYubiKeyDevice, op: (Ctap2Session, CommandState) -> Map<String, Any?>) {
    if (synchronized(lock) { pending == null }) return
    device.setOnClosed { emit("usb", "removed") }
    if (device.hasPermission()) {
      emit("usb", "connected")
      runOn(device, "usb", op)
      return
    }
    emit("usb", "permission")
    val action = ctx.packageName + ".WARDENCLAW_YUBIKEY_USB_PERMISSION"
    val receiver = object : BroadcastReceiver() {
      override fun onReceive(c: Context, intent: Intent) {
        unregisterPerm(ctx)
        if (intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)) {
          emit("usb", "connected")
          runOn(device, "usb", op)
        } else {
          emit("usb", "permission-denied")
          finish(null, YubikeyException("USB_PERMISSION_DENIED", "USB access to the key was not allowed"))
        }
      }
    }
    unregisterPerm(ctx)
    permReceiver = receiver
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      ctx.registerReceiver(receiver, IntentFilter(action), Context.RECEIVER_NOT_EXPORTED)
    } else {
      @Suppress("UnspecifiedRegisterReceiverFlag")
      ctx.registerReceiver(receiver, IntentFilter(action))
    }
    // FLAG_MUTABLE is required: the system adds EXTRA_PERMISSION_GRANTED to the intent. The intent is explicit (setPackage).
    val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0
    val pi = PendingIntent.getBroadcast(ctx, 0, Intent(action).setPackage(ctx.packageName), flags)
    (ctx.getSystemService(Context.USB_SERVICE) as UsbManager).requestPermission(device.usbDevice, pi)
  }

  private fun unregisterPerm(ctx: Context) {
    val r = permReceiver ?: return
    permReceiver = null
    try {
      ctx.unregisterReceiver(r)
    } catch (_: Exception) {
    }
  }

  /** Exchange with the found key (NFC or USB). The other transport is ignored meanwhile. */
  private fun runOn(device: YubiKeyDevice, transport: String, op: (Ctap2Session, CommandState) -> Map<String, Any?>) {
    val cmd: CommandState
    synchronized(lock) {
      if (pending == null || busy) return
      cmd = state ?: return
      busy = true
    }
    val work = Runnable {
      try {
        val result = if (device is UsbYubiKeyDevice && device.supportsConnection(FidoConnection::class.java)) {
          device.openConnection(FidoConnection::class.java).use { conn -> op(Ctap2Session(conn), cmd) }
        } else {
          device.openConnection(SmartCardConnection::class.java).use { conn -> op(Ctap2Session(conn), cmd) }
        }
        finish(result, null)
      } catch (e: CtapException) {
        if (e.ctapError == CtapException.ERR_KEEPALIVE_CANCEL) finish(null, YubikeyException("CANCELLED", "cancelled"))
        else finish(null, mapCtap(e))
      } catch (e: YubikeyException) {
        finish(null, e)
      } catch (e: IOException) {
        // NFC: the tag was removed too early; USB: the key was pulled out. Wait for another tap/plug-in
        Log.i(TAG, "$transport: connection lost, waiting again: ${e.message}")
        synchronized(lock) { busy = false }
      } catch (e: Exception) {
        finish(null, YubikeyException("FAILED", e.message ?: e.javaClass.simpleName, e))
      }
    }
    // The NFC callback already arrives off the main thread, the USB one on the main thread (broadcast):
    // move that one to the background, the USB exchange blocks until the contact is touched.
    if (transport == "usb") Thread(work, "yubikey-usb").start() else work.run()
  }

  private fun finish(result: Map<String, Any?>?, error: CodedException?) {
    val p: Promise
    val act: Activity?
    val cmd: CommandState?
    synchronized(lock) {
      p = pending ?: return
      pending = null
      act = activity
      activity = null
      cmd = state
      state = null
      busy = false
    }
    cmd?.cancel()
    timeout?.let { main.removeCallbacks(it) }
    timeout = null
    main.post {
      if (nfcOn) act?.let { a -> manager?.stopNfcDiscovery(a) }
      nfcOn = false
      if (usbOn) manager?.stopUsbDiscovery()
      usbOn = false
      act?.applicationContext?.let { unregisterPerm(it) }
    }
    if (error != null) p.reject(error) else p.resolve(result)
  }

  private fun mapCtap(e: CtapException): YubikeyException {
    val code = when (e.ctapError) {
      CtapException.ERR_PUAT_REQUIRED -> "PIN_REQUIRED"
      CtapException.ERR_PIN_INVALID -> "PIN_INVALID"
      CtapException.ERR_PIN_BLOCKED, CtapException.ERR_PIN_AUTH_BLOCKED -> "PIN_BLOCKED"
      CtapException.ERR_NO_CREDENTIALS -> "NO_CREDENTIALS"
      CtapException.ERR_OPERATION_DENIED, CtapException.ERR_NOT_ALLOWED -> "DENIED"
      CtapException.ERR_UNSUPPORTED_ALGORITHM -> "UNSUPPORTED_ALGORITHM"
      CtapException.ERR_ACTION_TIMEOUT, CtapException.ERR_USER_ACTION_TIMEOUT -> "TIMEOUT"
      else -> "CTAP_ERROR"
    }
    return YubikeyException(code, "CTAP 0x%02x: %s".format(e.ctapError, e.message ?: ""), e)
  }
}

private fun b64(b: ByteArray): String = Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

private fun unb64(s: String): ByteArray = Base64.decode(s, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
