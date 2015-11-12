# Hook
You can hook system process like system_server in Android 5.0+ devices.
#How to build?
1 You should download ndk-r10c and export ndk root path to your bash profile.<br/>
2 Then enter Hook/jni path and input ndk-build.

#How to use?
You should ensure that your device is root firstly. <br/>
1 Use `adb push ../libs/armeabi/inject to /data/tmp/local`<br/>
2 Then `adb push ../libs/armeabi/libpayload.so to /system/lib`<br/>
3 Next `adb shell`<br/>
4 Next `su`<br/>
5 Last `./data/tmp/local/inject`<br/>

When adb shows `Read-Only FileSystem`, you should input `mount -o remount rw /system` in super status.
