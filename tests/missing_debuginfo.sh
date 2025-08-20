#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#
# Ensure correct behaviour for missing/debuglink DWARF.

outdir=

fail()
{
	# Do not remove test dir; might be useful for analysis
	trap - EXIT
	if [[ -d "$outdir" ]]; then
		echo "Test data is in $outdir"
	fi
	exit 1
}

cleanup()
{
	rm ${outdir}/*
	rmdir $outdir
}

vmlinux=${vmlinux:-$1}

if [ -z "$vmlinux" ] ; then
	vmlinux=$(pahole --running_kernel_vmlinux 2>/dev/null)
fi

outdir=$(mktemp -d /tmp/missing_debuginfo.sh.XXXXXX)

trap cleanup EXIT

echo -n "Validation of correct behaviour with missing/debuglink DWARF: "

emptyfile=$outdir/emptyfile
touch $emptyfile
pahole --btf_features=default --btf_encode_detached=$emptyfile.btf $emptyfile
ret=$?
if [[ $ret -ne 0 ]]; then
	echo "non-zero return value $ret for empty file with no debug info"
	fail
fi
if [[ -f $emptyfile.btf ]]; then
	echo "$emptyfile.btf should not exist"
	fail
fi

if [[ -f "$vmlinux" ]]; then
	debuginfo=$outdir/vmlinux.debug
	objcopy --only-keep-debug $vmlinux $debuginfo
	objcopy --strip-all --add-gnu-debuglink=$debuginfo $vmlinux $outdir/vmlinux.stripped
	pahole --btf_features=default --btf_encode_detached=$outdir/debuglink.btf $outdir/vmlinux.stripped 2>/dev/null
	ret=$?
	if [[ $ret -ne 0 ]]; then
		echo "non-zero return value $ret for stripped vmlinux $vmlinux with debuglink"
		fail
	fi
	if [[ -f $outdir/debuglink.btf ]]; then
		echo "$outdir/debuglink.btf should not exist"
		fail
	fi
fi

echo "Ok"
exit 0
