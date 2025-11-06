# Dumping Android CamX register accesses

## Magisk and adb root
Install on the device magisk to get root access.

Then install the ADB root enabler
https://github.com/anasfanani/Adb-Root-Enabler

Disable the SELinux and verify
```
adb shell su -c 'setenforce 0'
adb shell getenforce
Permissive
```

