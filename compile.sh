#!/bin/bash
echo "[*] Compiling async_wake_ios.."
$(which xcodebuild) clean build CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" -sdk `xcrun --sdk iphoneos --show-sdk-path` -arch arm64
mv build/Release-iphoneos/async_wake_ios.app async_wake_ios.app
mkdir Payload
mv async_wake_ios.app Payload/async_wake_ios.app
echo "[*] Zipping into .ipa"
zip -r9 async_wake_ios.ipa Payload/async_wake_ios.app
rm -rf build Payload
echo "[*] Done! Install .ipa with Impactor"
