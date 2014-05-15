#
# Copyright (C) 2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk

ARCH:=arm
BOARD:=oxnas
BOARDNAME:=PLXTECH NAS782X
DEVICE_TYPE:=nas
FEATURES:=gpio pcie usb usbgadget ext4 targz ubifs rtc
CPU_TYPE:=mpcore

MAINTAINER:=Daniel Golle <daniel.golle@gmail.com>

LINUX_VERSION:=3.14.4

include $(INCLUDE_DIR)/target.mk

DEFAULT_PACKAGES += \
	kmod-button-hotplug kmod-input-gpio-keys-polled kmod-leds-gpio \
	kmod-i2c-gpio usbutils ubi-utils \
	uboot-envtools uboot-oxnas-ox820

KERNELNAME:="zImage dtbs"

$(eval $(call BuildTarget))
