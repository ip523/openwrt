#
# Copyright (C) 2014 OpenWrt.org
#

. /lib/oxnas.sh

RAMFS_COPY_DATA=/lib/oxnas.sh
# combined-image uses 64k blocks
CI_BLKSZ=65536
# 'data' partition on NAND contains UBI
CI_UBIPART="data"

platform_find_volume() {
	local first dev size erasesize name
	for ubidevdir in /sys/devices/virtual/ubi/ubi*; do
		[ ! -d "$ubidevdir" ] && continue;
		bname=$( basename $ubidevdir )
		for ubivoldir in $ubidevdir/${bname}_*; do
			[ ! -d "$ubivoldir" ] && continue;
			[ "$( cat $ubivoldir/name )" = "$1" ] &&
				basename $ubivoldir
		done
	done
}

platform_restore_config() {
	data_ubivol="$( platform_find_volume rootfs_data )"
	mkdir /tmp/new_root
	mount -t ubifs /dev/$data_ubivol /tmp/new_root
	mv "$1" "/tmp/new_root/sysupgrade.tgz"
	umount /tmp/new_root
	rmdir /tmp/new_root
}

platform_do_upgrade_ubinized() {
	local upgrade_image="$1"
	local conf_tar="$2"
	local save_config="$3"
	local mtdnum="$( find_mtd_index "$CI_UBIPART" )"
	if [ ! "$mtdnum" ]; then
		echo "cannot find mtd device $CI_UBIPART"
		return 1;
	fi
	local mtddev="/dev/mtd${mtdnum}"
	ubidetach -p "${mtddev}"
	sync
	ubiformat "${mtddev}" -y -f "$upgrade_image"
	ubiattach -p "${mtddev}"
	sync
	if [ -f "$conf_tar" -a "$save_config" -eq 1 ]; then
		platform_restore_config "$conf_tar"
	fi
	return 0;
}

platform_do_upgrade_combined_ubi() {
	local upgrade_image="$1"
	local conf_tar="$2"
	local save_config="$3"
	local kern_length_hex=0x$(dd if="$upgrade_image" bs=2 skip=1 count=4 2>/dev/null)
	local kern_length=$( printf "%u" "$kern_length_hex" )
	local kern_blocks=$(($kern_length / $CI_BLKSZ))
	local root_length_hex=0x$(dd if="$upgrade_image" bs=2 skip=5 count=4 2>/dev/null)
	local root_length=$( printf "%u" "$root_length_hex" )
	local root_blocks=$(($root_length / $CI_BLKSZ))

	local kern_ubivol="$( platform_find_volume boot )"
	local root_ubivol="$( platform_find_volume rootfs )"
	local data_ubivol="$( platform_find_volume rootfs_data )"

	# remove ubiblock device of rootfs
	local root_ubiblk="ubiblock${root_ubivol:3}"
	if [ "$root_ubiblk" -a -e "/dev/$root_ubiblk" ]; then
		echo "removing $root_ubiblk"
		if ! ubiblock -r /dev/$root_ubivol; then
			echo "cannot remove $root_ubiblk"
			return 1;
		fi
	fi

	if [ ! "$kern_ubivol" ]; then
		echo "cannot find needed ubi volumes, flash ubinized image to re-format the NAND"
		return 1;
	fi

	local ubidev="$( echo $kern_ubivol | cut -d'_' -f1 )"

	# kill rootfs volume
	if [ "$root_ubivol" ]; then
		ubirmvol /dev/$ubidev -N rootfs || true
	fi
	# kill rootfs_data volume
	if [ "$data_ubivol" ]; then
		ubirmvol /dev/$ubidev -N rootfs_data || true
	fi

	# update root.squashfs
	if ! ubirsvol /dev/$ubidev -N kernel -s $kern_length; then
		echo "cannot resize rootfs volume $kern_ubivol"
		return 1;
	fi
	( dd if="$upgrade_image" bs=$CI_BLKSZ skip=1 count=$kern_blocks 2>/dev/null ) | \
		ubiupdatevol /dev/$kern_ubivol -s $kern_length -

	if ! ubimkvol /dev/$ubidev -N rootfs -s $root_length; then
	fi
	root_ubivol="$( platform_find_volume rootfs )"

	dd if="$upgrade_image" bs=$CI_BLKSZ skip=$((1+$kern_blocks)) count=$root_blocks 2>/dev/null | \
		ubiupdatevol /dev/$root_ubivol -s $root_length -

	# re-create rootfs_data
	if ! ubimkvol /dev/$ubidev -N rootfs_data -m; then
		echo "cannot initialize rootfs_data volume"
		return 1
	fi

	if [ -f "$conf_tar" -a "$save_config" -eq 1 ]; then
		platform_restore_config "$conf_tar"
	fi
	echo "sysupgrade successfull"
	return 0
}

platform_check_image() {
	local board=$(oxnas_board_name)
	local magic="$(get_magic_word "$1")"
	local magic_long="$(get_magic_long "$1")"

	[ "$ARGC" -gt 1 ] && return 1

	case "$board" in
	stg-212)
		# ubinized image
		[ "$magic_long" = "55424923" ] && {
			return 0
		}
		# borrow OpenWrt's good-old combine-image format
		[ "$magic" != "4349" ] && {
			echo "Invalid image. Use *-sysupgrade.bin files on this board"
			return 1
		}

		local md5_img=$(dd if="$1" bs=2 skip=9 count=16 2>/dev/null)
		local md5_chk=$(dd if="$1" bs=$CI_BLKSZ skip=1 2>/dev/null | md5sum -); md5_chk="${md5_chk%% *}"

		if [ -n "$md5_img" -a -n "$md5_chk" ] && [ "$md5_img" = "$md5_chk" ]; then
			return 0
		else
			echo "Invalid image. Contents do not match checksum (image:$md5_img calculated:$md5_chk)"
			return 1
		fi
		return 0
		;;
	esac

	echo "Sysupgrade is not yet supported on $board."
	return 1
}

platform_write_rcstop() {
	cat <<-EOT > /etc/rcStop
		#!/bin/sh
		. /lib/functions.sh
		. /lib/upgrade/common.sh
		. /lib/upgrade/platform.sh
		cd "$(pwd)"
		platform_do_upgrade_phase2 "$1" "$CONF_TAR" "$SAVE_CONFIG"
	EOT
	chmod +x /etc/rcStop
}

platform_do_upgrade() {
	platform_write_rcstop "$1"
	exec kill -USR2 1
}

platform_do_upgrade_phase2() {
	if [ ! -r "$1" ]; then
		echo "cannot find upgrade image"
		return 1;
	fi

	# we're now pid1, kill *any* remaining process, even whitelisted ones
	for pid in /proc/[0-9]*/cmdline; do
		pid="${pid#/proc/}"; pid="${pid%/cmdline}"
		[ "$pid" != 1 ] && kill -9 "$pid" 2>/dev/null
	done

	# additionally required cleanup steps should go here
	# sysupgrade already lazily umounts /mnt (the old rootfs)
	# after replacing init and killingthe last old processes above
	# it *should* be free for reflashing...

	local board=$(oxnas_board_name)
	local magic_long="$(get_magic_long "$1")"
	local magic="$(get_magic_word "$1")"

	case "$board" in
	stg-212)
		# ubinized flash image
		[ "$magic_long" = "55424923" ] && {
			platform_do_upgrade_ubinized "$1" "$2" "$3"
			return 0
		}
		# borrow OpenWrt's good-old combine-image format
		[ "$magic" = "4349" ] && {
			platform_do_upgrade_combined_ubi "$1" "$2" "$3"
			return 0
		}
		;;
	*)
		default_do_upgrade "$1" "$2" "$3"
		;;
	esac
}

disable_watchdog() {
	killall watchdog
	( ps | grep -v 'grep' | grep '/dev/watchdog' ) && {
		echo 'Could not disable watchdog'
		return 1
	}
}

append sysupgrade_pre_upgrade disable_watchdog
