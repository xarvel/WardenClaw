# SPDX-License-Identifier: GPL-3.0-or-later
# Local Expo module "wardenpush" (iOS only): notifications for the iPhone itself. APNs token for
# wardend (/v1/push/register), permission, taps on a notification. No third-party push service.
Pod::Spec.new do |s|
  s.name           = 'WardenPush'
  s.version        = '0.1.0'
  s.summary        = 'WardenClaw: APNs notifications about approval requests on the iPhone'
  s.license        = 'GPL-3.0-or-later'
  s.author         = 'WardenClaw'
  s.homepage       = 'https://wardenclaw.dev'
  s.platforms      = { :ios => '16.4' }
  s.swift_version  = '5.9'
  s.source         = { :git => 'https://github.com/xarvel/WardenClaw.git' }
  s.static_framework = true

  s.dependency 'ExpoModulesCore'
  s.frameworks = 'UserNotifications'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'SWIFT_COMPILATION_MODE' => 'wholemodule'
  }

  s.source_files = '**/*.{h,m,swift}'
end
