PC Pulse v0.2 Cloud Build
=========================

Windows/
    Run the PC monitoring server and generate its QR code.

iPhone/
    Native SwiftUI app source.

codemagic.yaml
    Cloud build workflow that compiles the iPhone app on macOS/Xcode and
    creates an unsigned device IPA.

CLOUD_BUILD_STEPS.txt
    Follow this file to turn the SwiftUI source into PCPulse_unsigned.ipa.

QUICK TEST
----------
You already confirmed the Windows QR dashboard works in Safari.
The next milestone is building the native iPhone IPA using Codemagic.
