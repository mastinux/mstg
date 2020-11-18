#!/bin/bash

dx \
	--dex \
	--output=classes.dex \
	CodeInjection.jar

jar cfv lib.jar classes.dex

adb shell rm /sdcard/libcodeinjection.jar
adb push lib.jar /sdcard/libcodeinjection.jar

rm classes.dex
rm lib.jar

adb shell ls -l /sdcard/libcodeinjection.jar
