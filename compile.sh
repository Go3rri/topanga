#!/bin/bash
echo "[*] Compiling topanga.."
$(which xcodebuild) clean build CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" -sdk `xcrun --sdk iphoneos --show-sdk-path` -arch arm64
mv build/Release-iphoneos/topanga.app topanga.app
mkdir Payload
mv topanga.app Payload/topanga.app
echo "[*] Zipping into .ipa"
zip -r9 topanga.ipa Payload/topanga.app
rm -rf build Payload
echo "[*] Done! Install .ipa with Impactor"
