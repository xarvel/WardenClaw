# SPDX-License-Identifier: GPL-3.0-or-later
# Local Expo module "applewatch" (iOS only): WatchConnectivity, used to hand a wardend pairing link
# to the WardenClaw Apple Watch app (targets/watch). The watch does everything else itself.
Pod::Spec.new do |s|
  s.name           = 'AppleWatch'
  s.version        = '0.1.0'
  s.summary        = 'WardenClaw: send a pairing link to the Apple Watch app'
  s.license        = 'GPL-3.0-or-later'
  s.author         = 'WardenClaw'
  s.homepage       = 'https://wardenclaw.dev'
  s.platforms      = { :ios => '16.4' }
  s.swift_version  = '5.9'
  s.source         = { :git => 'https://github.com/xarvel/WardenClaw.git' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'
  s.frameworks = 'WatchConnectivity'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = '**/*.{h,m,swift}'
end
