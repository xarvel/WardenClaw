# SPDX-License-Identifier: GPL-3.0-or-later
Pod::Spec.new do |s|
  s.name           = 'BenchProbe'
  s.version        = '0.1.0'
  s.summary        = 'WardenClaw on-device judge benchmark probe'
  s.license        = 'GPL-3.0-or-later'
  s.author         = 'WardenClaw'
  s.homepage       = 'https://wardenclaw.dev'
  s.platforms      = { :ios => '16.4' }
  s.swift_version  = '5.9'
  s.source         = { :git => 'https://github.com/xarvel/WardenClaw.git' }
  s.static_framework = true
  s.dependency 'ExpoModulesCore'
  s.frameworks = 'UIKit', 'CryptoKit'
  s.source_files = '**/*.swift'
end
