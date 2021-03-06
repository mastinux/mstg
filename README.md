# MSTG & MSTG Hacking Playground

## Mobile Security Testing Guide

> https://github.com/OWASP/owasp-mstg/releases/download/1.1.3-excel/MSTG-EN.pdf

#### General Mobile App Testing Guide

- [Mobile App Authentication Architectures](./MSTG/README-MSTG-MAAA.md)
- [Testing Network Communication](./MSTG/README-MSTG-TNC.md)
- [Cryptography for Mobile Apps](./MSTG/README-MSTG-CMA.md)
- [Testing Code Quality](./MSTG/README-MSTG-TCQ.md)
- [Tampering and Reverse Engineering](./MSTG/README-MSTG-TRE.md)
- [Testing User Interaction](./MSTG/README-MSTG-TUI.md)

#### Android Testing Guide

- [Android Platform Overview](./MSTG/README-MSTG-APO.md)
- [Android Basic Security Testing](./MSTG/README-MSTG-ABST.md)
- [Data Storage on Android](./MSTG/README-MSTG-DSA.md)
- [Android Cryptographic APIs](./MSTG/README-MSTG-ACA.md)
- [Local Authentication on Android](./MSTG/README-MSTG-LAA.md)
- [Android Network APIs](./MSTG/README-MSTG-ANA.md)
- [Android Platform APIs](./MSTG/README-MSTG-APA.md)
- [Code Quality and Build Settings for Android Apps](./MSTG/README-MSTG-CQBSAA.md)
- [Tampering and Reverse Engineering on Android](./MSTG/README-MSTG-TREA.md) #TODO
- [Android Anti-Reversing Defenses](./MSTG/README-MSTG-AARD.md) #TODO

#### iOS Testing Guide

- #TODO

----------

## MSTG Hacking Playground

> https://github.com/OWASP/MSTG-Hacking-Playground

#### Setup

`$ adb install MSTG-Hacking-Playground/Android/MSTG-Android-Java-App/app/app-x86-debug.apk`

#### Test Cases

> hints can be found here  
> https://github.com/OWASP/MSTG-Hacking-Playground/wiki/Android-App  
> https://github.com/bwinsight/mobile-omtg

- [OMTG-DATAST-001-BADENCRYPTION](./OMTG/README-OMTG-DATAST-001-BADENCRYPTION.md)
- [OMTG-DATAST-001-KEYCHAIN](./OMTG/README-OMTG-DATAST-001-KEYCHAIN.md)
- [OMTG-DATAST-001-KEYSTORE](./OMTG/README-OMTG-DATAST-001-KEYSTORE.md)
- [OMTG-DATAST-001-INTERNALSTORAGE](./OMTG/README-OMTG-DATAST-001-INTERNALSTORAGE.md)
- [OMTG-DATAST-001-EXTERNALSTORAGE](./OMTG/README-OMTG-DATAST-001-EXTERNALSTORAGE.md)
- [OMTG-DATAST-001-SHAREDPREFERENCES](./OMTG/README-OMTG-DATAST-001-SHAREDPREFERENCES.md)
- [OMTG-DATAST-001-SQLITE](./OMTG/README-OMTG-DATAST-001-SQLITE.md)
- [OMTG-DATAST-001-SQLITE-ENCRYPTED](./OMTG/README-OMTG-DATAST-001-SQLITE-ENCRYPTED.md)
- [OMTG-DATAST-002-LOGGING](./OMTG/README-OMTG-DATAST-002-LOGGING.md)
- [OMTG-DATAST-005-KEYBOARD-CACHE](./OMTG/README-OMTG-DATAST-005-KEYBOARD-CACHE.md)
- [OMTG-DATAST-006-CLIPBOARD](./OMTG/README-OMTG-DATAST-006-CLIPBOARD.md)
- [OMTG-DATAST-011-MEMORY](./OMTG/README-OMTG-DATAST-011-MEMORY.md)
- [OMTG-ENV-005-WEBVIEW-REMOTE](./OMTG/README-OMTG-ENV-005-WEBVIEW-REMOTE.md)
- [OMTG-ENV-005-WEBVIEW-LOCAL](./OMTG/README-OMTG-ENV-005-WEBVIEW-LOCAL.md)
- [OMTG-CODING-003-BEST-PRACTICE](./OMTG/README-OMTG-CODING-003-BEST-PRACTICE.md)
- [OMTG-CODING-003-SQL-INJECTION](./OMTG/README-OMTG-CODING-003-SQL-INJECTION.md)
- [OMTG-CODING-003-SQL-INJECTION-CONTENT-PROVIDER](./OMTG/README-OMTG-CODING-003-SQL-INJECTION-CONTENT-PROVIDER.md)
- [OMTG-CODING-004-CODE-INJECTION](./OMTG/README-OMTG-CODING-004-CODE-INJECTION.md) #FIXME
- [OMTG-NETW-001-SECURE-CHANNEL](./OMTG/README-OMTG-NETW-001-SECURE-CHANNEL.md)
- [OMTG-NETW-004-SSL-PINNING](./OMTG/README-OMTG-NETW-004-SSL-PINNING.md)
- [OMTG-NETW-004-SSL-PINNING-CERTIFICATE](./OMTG/README-OMTG-NETW-004-SSL-PINNING-CERTIFICATE.md) #TODO

----------

## UnCrackable Mobile Apps

> https://github.com/OWASP/owasp-mstg/tree/master/Crackmes

- [UnCrackable App for Android Level 1](./Crackmes/AndroidLicenceValidator.md)
<!--
UnCrackableAppAndroid1.md
UnCrackableAppAndroid2.md
UnCrackableAppAndroid3.md
UnCrackableAppAndroid4.md
UnCrackableAppiOS1.md
UnCrackableAppiOS2.md
-->
