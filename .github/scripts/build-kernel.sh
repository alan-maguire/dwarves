#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#

GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-$(dirname $0)/../..}
INPUTS_ARCH=${INPUTS_ARCH:-$(uname -m)}
REPO=${REPO:-https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git}
REPO_BRANCH=${REPO_BRANCH:-master}
REPO_TARGET=${GITHUB_WORKSPACE}/.kernel
CC=${CC:-gcc}
LLVM_VERSION=${LLVM_VERSION:-22}
LTO=${LTO:-none}

export PATH=${GITHUB_WORKSPACE}/install/usr/local/bin:${PATH}
export PAHOLE=${GITHUB_WORKSPACE}/install/usr/local/bin/pahole

which pahole
$PAHOLE --version

# In CI, get-kernel-source.sh has already fetched the source.
if [[ ! -d $REPO_TARGET ]]; then
	git clone --depth=1 --branch $REPO_BRANCH $REPO $REPO_TARGET
fi
cd $REPO_TARGET

buildopts=
if [[ "$CC" = "clang" ]]; then
	buildopts="LLVM=-${LLVM_VERSION}"
	echo "Building with $buildopts"
fi

cat tools/testing/selftests/bpf/config \
    tools/testing/selftests/bpf/config.${INPUTS_ARCH} > .config
# this file might or might not exist depending on kernel version
if [[ -f tools/testing/selftests/bpf/config.vm ]]; then
	cat tools/testing/selftests/bpf/config.vm >> .config
fi
make $buildopts olddefconfig

case "$LTO" in
none)
	;;
thin)
	if [[ "$CC" != "clang" ]]; then
		echo "LTO=thin requires CC=clang" >&2
		exit 1
	fi
	echo "Enabling Clang ThinLTO"
	scripts/config -d LTO_NONE -e LTO_CLANG_THIN
	make $buildopts olddefconfig
	# olddefconfig silently falls back to LTO_NONE if a dependency
	# is not met (e.g. KASAN, GCOV); fail rather than test non-LTO.
	if ! grep -q '^CONFIG_LTO_CLANG_THIN=y' .config; then
		echo "CONFIG_LTO_CLANG_THIN could not be enabled:" >&2
		grep -E 'LTO|HAS_LTO' .config >&2
		exit 1
	fi
	;;
*)
	echo "Unsupported LTO mode '$LTO'" >&2
	exit 1
	;;
esac

make $buildopts prepare
cat .config
make -j $((4*$(nproc))) $buildopts all

# Build, install bpftool
cd tools/bpf/bpftool
LLVM_STRIP=llvm-strip-${LLVM_VERSION} make && make DESTDIR=${GITHUB_WORKSPACE}/install/ install
