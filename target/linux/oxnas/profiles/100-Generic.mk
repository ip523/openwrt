#
# Copyright (C) 2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define Profile/POGOPLUGPRO
  NAME:=PogoPlug Pro/v3
  PACKAGES:= uboot-envtools kmod-usb2-oxnas
endef

define Profile/POGOPLUGPRO/Description
 Package set compatible with most OXNAS based boards.
endef

define Profile/STG212
  NAME:=MitraStar STG-212
  PACKAGES:= \
	uboot-envtools kmod-usb2-oxnas
endef

define Profile/STG212/Description
 Profile with built-in ox820 STG-212 board device-tree
endef

define Profile/KD20
  NAME:=Shuttle KD20
  PACKAGES:= \
	uboot-envtools kmod-usb2-oxnas kmod-usb3 kmod-rtc-pcf8563
endef

define Profile/KD20/Description
 Profile with built-in ox820 KD20 board device-tree
endef

$(eval $(call Profile,POGOPLUGPRO))
$(eval $(call Profile,STG212))
$(eval $(call Profile,KD20))
