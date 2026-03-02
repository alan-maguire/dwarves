#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2026, Oracle and/or its affiliates.
#
# Common helper functions for the testsuite.
#

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	echo "This script is meant to be sourced. Please use 'source test_lib.sh'."
	exit 1
fi

check_color_support()
{
	if [ ! -z "$RED" ] ; then
		return 0
	else
		if tput colors >/dev/null 2>&1; then
			num_colors=$(tput colors)
			if [ $num_colors -gt 0 ]; then
				RED='\033[0;31m'
				GREEN='\033[0;32m'
				YELLOW='\033[0;33m'
				NC='\033[0m'
			else
				RED=''
				GREEN=''
				YELLOW=''
				NC=''
			fi
		else
			RED=''
			GREEN=''
			YELLOW=''
			NC=''
		fi
	fi
	return 0
}

get_vmlinux()
{
	check_color_support
	vmlinux=${vmlinux:-$1}

	if [ -z "$vmlinux" ] ; then
		vmlinux=$(pahole --running_kernel_vmlinux)
		if [ -z "$vmlinux" ] ; then
			echo -e "${RED}Please specify a vmlinux file to operate on${NC}"
			exit 2
		fi
	fi

	if [ ! -f "$vmlinux" ] ; then
		echo "${RED}$vmlinux file not available, please specify another${NC}"
		exit 2
	fi

	echo $vmlinux
	return 0
}

make_tmpdir()
{
	outdir=$(mktemp -d /tmp/$0.XXXXXX)
	echo $outdir
	return 0
}

make_tmpobj()
{
	outobj=$(mktemp $outdir/$0.obj.XXXXXX.o)
	echo $outobj
	return 0
}

make_tmpsrc()
{
	outsrc=$(mktemp $outdir/$0.src.XXXXXX.c)
	echo $outsrc
	return 0
}

make_tmpfile()
{
	outfile=$(mktemp $outdir/$0.data.XXXXXX)
	echo $outfile
	return 0
}

info_log()
{
	printf "   "
	echo $1
}

title_log()
{
	check_color_support
	echo -e "${YELLOW}$1${NC}"
}

verbose_log()
{
	if [[ -n "$VERBOSE" ]]; then
		printf "   "
		echo $1
	fi
}

error_log()
{
	check_color_support
	echo -e "${RED}$1${NC}"
}

test_softfail()
{
	if [ -z "$softfail_count" ] ; then
		softfail_count=1
	else
		((softfail_count++))
	fi
}

test_fail()
{
	trap - EXIT
	check_color_support
	echo -e "${RED}Test $0 failed${NC}"
	if [[ -d "$outdir" ]]; then
		echo -e "${RED}Test data is in $outdir${NC}"
	fi
	exit 1
}

check_softfail()
{
	check_color_support
	if [ ! -z "$softfail_count" ] ; then
		echo -e "${RED}Soft failures: $softfail_count${NC}"
		return 1
	else
		return 0
	fi
}

test_pass()
{
	check_color_support
	echo -e "${GREEN}Test $0 passed${NC}"
	exit 0
}

cleanup()
{
	rm ${outdir}/*
	rmdir $outdir
	return 0
}
