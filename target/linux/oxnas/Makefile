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
FEATURES:=gpio pcie usb usbgadgetubifs ramdisk rtc squashfs
CPU_TYPE:=mpcore

MAINTAINER:=Daniel Golle <daniel.golle@gmail.com>

LINUX_VERSION:=3.14.4

include $(INCLUDE_DIR)/target.mk

DEFAULT_PACKAGES += \
	kmod-button-hotplug kmod-input-gpio-keys-polled kmod-leds-gpio		\
	kmod-i2c-gpio mtd-utils mtd-utils-nandwrite mtd-utils-nanddump		\
	ubi-utils ubi-utils-ubiattach ubi-utils-ubiblock ubi-utils-ubidetach	\
	ubi-utils-ubiformat ubi-utils-ubimkvol ubi-utils-ubirmvol		\
	ubi-utils-ubirsvol ubi-utils-ubiupdatevol uboot-envtools		\
	uboot-oxnas-ox820

KERNELNAME:="zImage dtbs"

$(eval $(call BuildTarget))
