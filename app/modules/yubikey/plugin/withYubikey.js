// SPDX-License-Identifier: GPL-3.0-or-later
// Config plugin of the YubiKey module.
//
// Android: NFC permission and optional NFC / USB host features in the app manifest (yubikit declares
// them too; here they are explicit and independent of its version).
//
// iOS:
//   - entitlement com.apple.developer.nfc.readersession.formats = [TAG] (NFC Tag Reading capability
//     on the App ID; EAS turns it on when it syncs capabilities, by hand: developer.apple.com);
//   - Info.plist: NFCReaderUsageDescription (kept if app.json sets one) and the FIDO applet AID
//     A0000006472F0001 in com.apple.developer.nfc.readersession.iso7816.select-identifiers
//     (without it iOS never reports the YubiKey as an ISO 7816 tag);
//   - Podfile: YubiKit 4.7.0 from Yubico's git tag with modular headers (trunk stops at 4.4.0, and
//     the Swift module needs `import YubiKit`);
//   - option { lightning: true }: UISupportedExternalAccessoryProtocols = com.yubico.ylp for the
//     YubiKey 5Ci over Lightning. Off by default: App Store review then requires the app to be
//     registered in Yubico's MFi program. USB-C is not offered on iOS at all (YubiKit has no FIDO2
//     over USB-C), see ios/YubikeyModule.swift.
//
// In app.json: "plugins": [..., "./modules/yubikey/plugin/withYubikey"]
//          or  [..., ["./modules/yubikey/plugin/withYubikey", { "lightning": true }]]
const { withAndroidManifest, withEntitlementsPlist, withInfoPlist, withPodfile } = require("expo/config-plugins");

const FIDO_AID = "A0000006472F0001";
const NFC_USAGE = "NFC is only used to talk to your security key (YubiKey) when you approve a request.";
const YUBIKIT_POD = "pod 'YubiKit', :git => 'https://github.com/Yubico/yubikit-ios.git', :tag => '4.7.0', :modular_headers => true";
const POD_MARK = "# wardenclaw: YubiKit for modules/yubikey";

function ensure(list, name, extra) {
  const arr = list ?? [];
  if (!arr.some((x) => x?.$?.["android:name"] === name)) arr.push({ $: { "android:name": name, ...extra } });
  return arr;
}

function addUnique(list, value) {
  const arr = Array.isArray(list) ? list.slice() : [];
  if (!arr.includes(value)) arr.push(value);
  return arr;
}

/** Podfile text with the YubiKit line after `use_expo_modules!` (idempotent). */
function addYubikitPod(contents) {
  if (contents.includes(POD_MARK)) return contents;
  const re = /^([ \t]*)use_expo_modules!.*$/m;
  const m = re.exec(contents);
  if (!m) throw new Error("withYubikey: `use_expo_modules!` not found in ios/Podfile, cannot add the YubiKit pod");
  const indent = m[1];
  const insert = `${m[0]}\n${indent}${POD_MARK}\n${indent}${YUBIKIT_POD}`;
  return contents.slice(0, m.index) + insert + contents.slice(m.index + m[0].length);
}

function withYubikeyAndroid(config) {
  return withAndroidManifest(config, (cfg) => {
    const m = cfg.modResults.manifest;
    m["uses-permission"] = ensure(m["uses-permission"], "android.permission.NFC");
    m["uses-feature"] = ensure(m["uses-feature"], "android.hardware.nfc", { "android:required": "false" });
    m["uses-feature"] = ensure(m["uses-feature"], "android.hardware.usb.host", { "android:required": "false" });
    return cfg;
  });
}

function withYubikeyIos(config, opts) {
  config = withEntitlementsPlist(config, (cfg) => {
    cfg.modResults["com.apple.developer.nfc.readersession.formats"] = addUnique(cfg.modResults["com.apple.developer.nfc.readersession.formats"], "TAG");
    return cfg;
  });
  config = withInfoPlist(config, (cfg) => {
    const p = cfg.modResults;
    if (!p.NFCReaderUsageDescription) p.NFCReaderUsageDescription = NFC_USAGE;
    const key = "com.apple.developer.nfc.readersession.iso7816.select-identifiers";
    p[key] = addUnique(p[key], FIDO_AID);
    if (opts.lightning) p.UISupportedExternalAccessoryProtocols = addUnique(p.UISupportedExternalAccessoryProtocols, "com.yubico.ylp");
    return cfg;
  });
  config = withPodfile(config, (cfg) => {
    cfg.modResults.contents = addYubikitPod(cfg.modResults.contents);
    return cfg;
  });
  return config;
}

module.exports = function withYubikey(config, opts) {
  config = withYubikeyAndroid(config);
  config = withYubikeyIos(config, opts ?? {});
  return config;
};
module.exports.addYubikitPod = addYubikitPod;
