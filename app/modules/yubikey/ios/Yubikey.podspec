# SPDX-License-Identifier: GPL-3.0-or-later
# Local Expo module "yubikey", iOS part. YubiKit (Yubico, Apache-2.0) comes from the Podfile line
# that plugin/withYubikey.js adds (git tag 4.7.0 with modular headers: CocoaPods trunk stops at
# 4.4.0 and the pod does not define a module on its own).
Pod::Spec.new do |s|
  s.name           = 'Yubikey'
  s.version        = '0.1.0'
  s.summary        = 'WardenClaw: FIDO2 (CTAP2) with a YubiKey over NFC via YubiKit'
  s.license        = 'GPL-3.0-or-later'
  s.author         = 'WardenClaw'
  s.homepage       = 'https://wardenclaw.dev'
  s.platforms      = { :ios => '16.4' }
  s.swift_version  = '5.9'
  s.source         = { :git => 'https://github.com/xarvel/WardenClaw.git' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'
  s.dependency 'YubiKit', '>= 4.4.0'
  s.weak_framework = 'CoreNFC'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = '**/*.{h,m,swift}'
end
