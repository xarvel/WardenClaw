// SPDX-License-Identifier: GPL-3.0-or-later
// postinstall: patches for onnxruntime-react-native 1.24.3 targeting Gradle 9 / AGP 8.12 / RN 0.86 (New Architecture only).
// Idempotent; does nothing if the package is not present. Judge benchmark spike (docs/judge-bench-spike.md).
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";

const root = "node_modules/onnxruntime-react-native";
if (!existsSync(root)) process.exit(0);

// A) unimodule.json makes the package an "Expo module" for expo-modules-autolinking: the Gradle project
//    is linked, but OnnxruntimePackage does not appear in PackageList -> NativeModules.Onnxruntime === null
//    and "Cannot read property 'install' of null" on the first require (crash on Pixel 27.09, build 68e4fd01).
//    Without the file, the package uses the normal RN autolinking.
const uni = `${root}/unimodule.json`;
if (existsSync(uni)) {
  rmSync(uni);
  console.log("patch-ort: removed", uni);
}

// B) install() obtains CallInvoker via getCatalystInstance(), which does not exist in bridgeless mode (only a
//    deprecation shim is present); ReactContext.getJSCallInvokerHolder() is the correct path. install() errors go to logcat.
const j = `${root}/android/src/main/java/ai/onnxruntime/reactnative/OnnxruntimeModule.java`;
if (existsSync(j)) {
  let s = readFileSync(j, "utf8");
  if (!s.includes("// wardenclaw-patched")) {
    s = s
      .replace("getReactApplicationContext().getCatalystInstance().getJSCallInvokerHolder()", "getReactApplicationContext().getJSCallInvokerHolder()")
      .replace(/\} catch \(Exception e\) \{\n(\s*)return false;/, '} catch (Exception e) {\n$1android.util.Log.e("Onnxruntime", "install failed", e);\n$1return false;');
    writeFileSync(j, `// wardenclaw-patched\n${s}`);
    console.log("patch-ort: patched", j);
  }
}

// C) android/build.gradle
const p = `${root}/android/build.gradle`;
if (!existsSync(p)) process.exit(0);
let s = readFileSync(p, "utf8");
if (s.includes("// wardenclaw-patched")) process.exit(0);
const before = s;
// 1) the embedded buildscript with AGP 7.4.2 is not needed: AGP is already on the root classpath
s = s.replace(/buildscript \{[\s\S]*?\n\}\n/, "");
// 2) org.gradle.util.VersionNumber does not exist in Gradle 9; our RN is >= 0.71, the fbjni branch is not needed
s = s.replace(/\s*if \(VersionNumber\.parse\(REACT_NATIVE_VERSION\)[\s\S]*?\n  \}\n/, "\n");
// 3) test dependencies in api/implementation are not needed
s = s.replace(/\s*api "org\.mockito:mockito-core:[^"]+"\n/, "\n").replace(/\s*implementation "junit:junit:[^"]+"\n/, "\n");
// 4) native ORT pinned to the same version as the JS part, not latest.integration
s = s.replace(/onnxruntime-android:latest\.integration@aar/g, "onnxruntime-android:1.24.3@aar");
// 5) lintOptions is deprecated
s = s.replace(/\s*lintOptions \{[\s\S]*?\}\n/, "\n");
s = `// wardenclaw-patched\n${s}`;
if (s === before) process.exit(0);
writeFileSync(p, s);
console.log("patch-ort: patched", p);
