#
# Copyright (C) 2013 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/image.mk

STG212_UBI_OPTS = -m 2048 -p 128KiB -s 512
STG212_UBIFS_OPTS = -m 2048 -e 126KiB -c 4096
STG212_UBI_TEMPLATE = overlay
STG212_UBI_KERNELUIMAGE = fit-stg212.itb
STG212_UBI_ROOTFSIMAGE = root.squashfs

KD20_UBI_OPTS = -m 2048 -p 128KiB -s 512
KD20_UBIFS_OPTS = -m 2048 -e 126KiB -c 4096

POGOPLUGPRO_UBI_OPTS = -m 2048 -p 128KiB -s 512
POGOPLUGPRO_UBIFS_OPTS = -m 2048 -e 126KiB -c 4096

POGOPLUGV3_UBI_OPTS = -m 2048 -p 128KiB -s 512
POGOPLUGV3_UBIFS_OPTS = -m 2048 -e 126KiB -c 4096

define sanitize_profile_name
$(shell echo $(PROFILE) | tr '[:upper:]' '[:lower:]' | sed 's/_/-/g')
endef

define Image/BuildKernel/Template
	$(CP) $(LINUX_DIR)/arch/arm/boot/dts/ox820-$(1).dtb $(BIN_DIR)/$(IMG_PREFIX)-$(1).dtb

	$(call Image/BuildKernel/MkFIT,$(1),$(KDIR)/zImage,$(BIN_DIR)/$(IMG_PREFIX)-$(1).dtb,none,0x60008000,0x60008000)
	$(CP) $(KDIR)/fit-$(1).itb $(BIN_DIR)/$(IMG_PREFIX)-$(1)-fit-uImage.itb

 ifneq ($(CONFIG_TARGET_ROOTFS_INITRAMFS),)
	$(call Image/BuildKernel/MkFIT,$(1),$(KDIR)/zImage-initramfs,$(BIN_DIR)/$(IMG_PREFIX)-$(1).dtb,none,0x60008000,0x60008000,-initramfs)
	$(CP) $(KDIR)/fit-$(1)-initramfs.itb $(BIN_DIR)/$(IMG_PREFIX)-$(1)-fit-uImage-initramfs.itb
 endif

	$(CP) $(KDIR)/zImage $(BIN_DIR)/$(IMG_PREFIX)-zImage
	$(call Image/BuildKernel/MkuImage, \
		none, 0x60008000, 0x60008000, \
		$(BIN_DIR)/$(IMG_PREFIX)-zImage, \
		$(BIN_DIR)/$(IMG_PREFIX)-uImage \
	)

 ifneq ($(CONFIG_TARGET_ROOTFS_INITRAMFS),)
	$(CP) $(KDIR)/zImage-initramfs $(BIN_DIR)/$(IMG_PREFIX)-zImage-initramfs
	$(call Image/BuildKernel/MkuImage, \
		none, 0x60008000, 0x60008000, \
		$(BIN_DIR)/$(IMG_PREFIX)-zImage-initramfs, \
		$(BIN_DIR)/$(IMG_PREFIX)-uImage-initramfs \
	)
 endif
endef

define Image/InstallKernel/Template

 ifneq ($(CONFIG_TARGET_ROOTFS_INCLUDE_KERNEL),)
	$(INSTALL_DIR) $(TARGET_DIR)/boot
   ifneq ($(CONFIG_TARGET_ROOTFS_INCLUDE_UIMAGE),)
	$(CP) $(BIN_DIR)/$(IMG_PREFIX)-uImage $(TARGET_DIR)/boot/
	ln -sf $(IMG_PREFIX)-uImage $(TARGET_DIR)/boot/uImage
   endif
   ifneq ($(CONFIG_TARGET_ROOTFS_INCLUDE_ZIMAGE),)
	$(CP) $(BIN_DIR)/$(IMG_PREFIX)-zImage $(TARGET_DIR)/boot/
	ln -sf $(IMG_PREFIX)-zImage $(TARGET_DIR)/boot/zImage
   endif
   ifneq ($(CONFIG_TARGET_ROOTFS_INCLUDE_FIT),)
	$(CP) $(BIN_DIR)/$(IMG_PREFIX)-$(1)-fit-uImage.itb $(TARGET_DIR)/boot/
	ln -sf $(IMG_PREFIX)-$(1)-fit-uImage.itb $(TARGET_DIR)/boot/uImage.itb
   endif
 endif

 ifneq ($(CONFIG_TARGET_ROOTFS_INCLUDE_DTB),)
	$(INSTALL_DIR) $(TARGET_DIR)/boot
  ifneq ($(1),)
	$(CP) $(BIN_DIR)/$(IMG_PREFIX)-$(1).dtb $(TARGET_DIR)/boot/
	ln -sf $(IMG_PREFIX)-$(1).dtb $(TARGET_DIR)/boot/$(1).dtb
  endif
 endif
endef

define Image/Build/squashfs
	$(call prepare_generic_squashfs,$(KDIR)/root.$(1))

	dd if=$(KDIR)/root.$(1) of=$(BIN_DIR)/$(IMG_PREFIX)-rootfs.$(1) bs=128k conv=sync
	sh $(TOPDIR)/scripts/combined-image.sh \
		$(KDIR)/fit-$(call sanitize_profile_name).itb \
		$(KDIR)/root.$(1) \
		$(BIN_DIR)/$(IMG_PREFIX)-$(call sanitize_profile_name)-$(patsubst jffs2-%,jffs2,$(patsubst squashfs-%,squashfs,$(1)))-sysupgrade.bin
endef

define Image/mkfs/targz

	$(TAR) -czpf $(BIN_DIR)/$(IMG_PREFIX)-$(call sanitize_profile_name)-rootfs.tar.gz --numeric-owner --owner=0 --group=0 -C $(TARGET_DIR)/ .
endef

define Image/Build/ubifs

 ifneq ($($(PROFILE)_UBIFS_OPTS),)
	$(CP) $(KDIR)/root.ubifs $(BIN_DIR)/$(IMG_PREFIX)-$(call sanitize_profile_name)-rootfs.ubifs
 endif
endef

define Image/Build/ubi

 ifneq ($($(PROFILE)_UBI_OPTS),)
	#$(CP) $(KDIR)/root-$(PROFILE).ubi $(BIN_DIR)/$(IMG_PREFIX)-$(call sanitize_profile_name).ubi
 endif
endef

Image/BuildKernel/Template/POGOPLUGPRO=$(call Image/BuildKernel/Template,pogoplug-pro)
Image/InstallKernel/Template/POGOPLUGPRO=$(call Image/InstallKernel/Template,pogoplug-pro)

Image/BuildKernel/Template/POGOPLUGV3=$(call Image/BuildKernel/Template,pogoplug-v3)
Image/InstallKernel/Template/POGOPLUGV3=$(call Image/InstallKernel/Template,pogoplug-v3)

Image/BuildKernel/Template/STG212=$(call Image/BuildKernel/Template,stg212)
Image/InstallKernel/Template/STG212=$(call Image/InstallKernel/Template,stg212)

Image/BuildKernel/Template/KD20=$(call Image/BuildKernel/Template,kd20)
Image/InstallKernel/Template/KD20=$(call Image/InstallKernel/Template,kd20)

define Image/BuildKernel
	$(call Image/BuildKernel/Template/$(PROFILE))
endef

define Image/InstallKernel
	$(call Image/InstallKernel/Template/$(PROFILE))
endef

define Image/Build
	$(if $(Image/Build/$(1)), \
		$(call Image/Build/$(1),$(1)), \
		$(CP) $(KDIR)/root.$(1) $(BIN_DIR)/$(IMG_PREFIX)-$(call sanitize_profile_name)-$(1).img \
	)
endef

$(eval $(call BuildImage))
