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
	local ubidevdir ubivoldir
	ubidevdir="/sys/devices/virtual/ubi/$1"
	[ ! -d "$ubidevdir" ] && return 1
	for ubivoldir in $ubidevdir/${1}_*; do
		[ ! -d "$ubivoldir" ] && continue
		if [ "$( cat $ubivoldir/name )" = "$2" ]; then
			basename $ubivoldir
			return 0
		fi
	done
}

platform_find_ubi() {
	local ubidevdir ubidev mtdnum
	mtdnum="$( find_mtd_index $1 )"
	[ ! "$mtdnum" ] && return 1
	for ubidevdir in /sys/devices/virtual/ubi/ubi*; do
		[ ! -d "$ubidevdir" ] && continue
		cmtdnum="$( cat $ubidevdir/mtd_num )"
		[ ! "$mtdnum" ] && continue
		if [ "$mtdnum" = "$cmtdnum" ]; then
			ubidev=$( basename $ubidevdir )
			echo $ubidev
			return 0
		fi
	done
}

platform_restore_config() {
	local ubidev=$( platform_find_ubi $CI_UBIPART )
	local ubivol="$( platform_find_volume $ubidev rootfs_data )"
	[ ! "$ubivol" ] &&
		ubivol="$( platform_find_volume $ubidev rootfs )"
	mkdir /tmp/new_root
	if ! mount -t ubifs /dev/$ubivol /tmp/new_root; then
		echo "mounting ubifs $ubivol failed"
		rmdir /tmp/new_root
		return 1
	fi
	mv "$1" "/tmp/new_root/sysupgrade.tgz"
	umount /tmp/new_root
	sync
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
	ubidetach -p "${mtddev}" || true
	sync
	ubiformat "${mtddev}" -y -f "$upgrade_image"
	ubiattach -p "${mtddev}"
	sync
	if [ -f "$conf_tar" -a "$save_config" -eq 1 ]; then
		platform_restore_config "$conf_tar"
	fi
	return 0;
}

# get the first 4 bytes (magic) of a given file starting at offset in hex format
get_magic_long_at() {
	dd if="$2" skip=$1 bs=$CI_BLKSZ count=1 2>/dev/null | hexdump -v -n 4 -e '1/1 "%02x"'
}

identify() {
	local block;
	local magic=$( get_magic_long_at ${2:-0} "$1" )
	case "$magic" in
		"55424923")
			echo "ubi"
			;;
		"31181006")
			echo "ubifs"
			;;
		"68737173")
			echo "squashfs"
			;;
		"d00dfeed")
			echo "fit"
			;;
		"4349"*)
			echo "combined"
			;;
		*)
			echo "unknown"
			;;
	esac
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
	local root_fs="$( identify $upgrade_image $(( $kern_blocks + 1 )))"
	local mtdnum="$( find_mtd_index "$CI_UBIPART" )"
	echo "rootfs at $kern_blocks type $root_fs"
	if [ ! "$mtdnum" ]; then
		echo "cannot find ubi mtd partition $CI_UBIPART"
		return 1
	fi
	local ubidev="$( platform_find_ubi "$CI_UBIPART" )"
	if [ ! "$ubidev" ]; then
		ubiattach -m "$mtdnum"
		sync
		ubidev="$( platform_find_ubi "$CI_UBIPART" )"
	fi
	if [ ! "$ubidev" ]; then
		ubiformat /dev/mtd$mtdnum -y
		ubiattach -m "$mtdnum"
		sync
		ubidev="$( platform_find_ubi "$CI_UBIPART" )"
	fi
	local kern_ubivol="$( platform_find_volume $ubidev kernel )"
	local root_ubivol="$( platform_find_volume $ubidev rootfs )"
	local data_ubivol="$( platform_find_volume $ubidev rootfs_data )"

	# remove ubiblock device of rootfs
	local root_ubiblk="ubiblock${root_ubivol:3}"
	if [ "$root_ubivol" -a -e "/dev/$root_ubiblk" ]; then
		echo "removing $root_ubiblk"
		if ! ubiblock -r /dev/$root_ubivol; then
			echo "cannot remove $root_ubiblk"
			return 1;
		fi
	fi

	# kill volumes
	if [ "$kern_ubivol" ]; then
		ubirmvol /dev/$ubidev -N kernel || true
	fi
	if [ "$root_ubivol" ]; then
		ubirmvol /dev/$ubidev -N rootfs || true
	fi
	if [ "$data_ubivol" ]; then
		ubirmvol /dev/$ubidev -N rootfs_data || true
	fi

	# update rootfs
	if ! ubimkvol /dev/$ubidev -N kernel -s $kern_length; then
		echo "cannot create kernel volume"
		return 1;
	fi

	local root_size_param
	if [ "$root_fs" = "ubifs" ]; then
		root_size_param="-m"
	else
		root_size_param="-s $root_length"
	fi
	if ! ubimkvol /dev/$ubidev -N rootfs $root_size_param; then
		echo "cannot create rootfs volume"
		return 1;
	fi

	# create rootfs_data for non-ubifs rootfs
	if [ "$root_fs" != "ubifs" ]; then
		if ! ubimkvol /dev/$ubidev -N rootfs_data -m; then
			echo "cannot initialize rootfs_data volume"
			return 1
		fi
	fi

	local kern_ubivol="$( platform_find_volume $ubidev kernel )"
	local root_ubivol="$( platform_find_volume $ubidev rootfs )"

	dd if="$upgrade_image" bs=$CI_BLKSZ skip=1 count=$kern_blocks 2>/dev/null | \
		ubiupdatevol /dev/$kern_ubivol -s $kern_length -

	dd if="$upgrade_image" bs=$CI_BLKSZ skip=$((1+$kern_blocks)) count=$root_blocks 2>/dev/null | \
		ubiupdatevol /dev/$root_ubivol -s $root_length -

	if [ -f "$conf_tar" -a "$save_config" -eq 1 ]; then
		platform_restore_config "$conf_tar"
	fi
	echo "sysupgrade successfull"
	return 0
}

platform_check_image() {
	local board=$(oxnas_board_name)
	local imgtype="$(identify "$1")"

	[ "$ARGC" -gt 1 ] && return 1

	case "$board" in
	stg-212)
		case "$imgtype" in
			ubi)
				return 0
				;;
			combined)
				local md5_img=$(dd if="$1" bs=2 skip=9 count=16 2>/dev/null)
				local md5_chk=$(dd if="$1" bs=$CI_BLKSZ skip=1 2>/dev/null | md5sum -); md5_chk="${md5_chk%% *}"
				if [ -n "$md5_img" -a -n "$md5_chk" ] && [ "$md5_img" = "$md5_chk" ]; then
					return 0
				else
					echo "Invalid image. Contents do not match checksum (image:$md5_img calculated:$md5_chk)"
					return 1
				fi
				;;
			*)
				echo "Invalid image type $imgtype."
				return 1
				;;
		esac
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
	local imgtype="$(identify "$1")"

	case "$board" in
	stg-212)
		case "$imgtype" in
			ubi)
				platform_do_upgrade_ubinized "$1" "$2" "$3"
				;;
			combined)
				platform_do_upgrade_combined_ubi "$1" "$2" "$3"
				;;
		esac
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
