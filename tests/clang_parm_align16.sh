#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

source test_lib.sh

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Validation of BTF encoding of over-aligned arguments."

align16="${outdir}/align16"
CC=$(which clang 2>/dev/null)

if [[ -z "$CC" ]]; then
	info_log "skip: clang not available"
	test_skip
fi

arch=$(uname -m)
if [[ "$arch" != "aarch64" ]]; then
	info_log "skip: test is arm64 only, running on $arch"
	test_skip
fi

# arm64 makes an argument whose alignment is 16 start on an even-numbered
# argument register, so f_odd() passes a in x0, v in x2:x3 -- leaving x1 as a
# hole -- and b in x4.  pahole has to account for that hole, otherwise every
# parameter after v looks like it is in an unexpected register and the whole
# function is dropped from BTF.
cat > ${align16}.c << EOF
typedef unsigned long long u64;
struct box { __int128 v; };

__attribute__((noinline)) u64 f_even(u64 a, u64 b, __int128 v)
{ return a + b + (u64)v; }

__attribute__((noinline)) u64 f_odd(u64 a, __int128 v, u64 b)
{ return a + b + (u64)v; }

__attribute__((noinline)) u64 f_odd_tail(u64 a, __int128 v, u64 b, u64 c, u64 d)
{ return a + b + c + d + (u64)v; }

__attribute__((noinline)) u64 f_stack(u64 a, u64 b, u64 c, u64 d, u64 e, u64 f,
				      u64 g, __int128 v)
{ return a + b + c + d + e + f + g + (u64)v; }

__attribute__((noinline)) u64 f_box(u64 a, struct box s, u64 b)
{ return a + b + (u64)s.v; }

u64 (*keep[])() = { (u64(*)())f_even, (u64(*)())f_odd, (u64(*)())f_odd_tail,
		    (u64(*)())f_stack, (u64(*)())f_box };
EOF

${CC} -g -O2 -c -o ${align16}.o ${align16}.c 2>/dev/null
if [[ $? -ne 0 ]]; then
	info_log "skip: clang could not compile ${align16}.c"
	test_skip
fi

LLVM_OBJCOPY=objcopy pahole -J --btf_features=consistent_func ${align16}.o
if [[ $? -ne 0 ]]; then
	error_log "Could not encode BTF for ${align16}.o"
	test_fail
fi

for fn in f_even f_odd f_odd_tail f_stack f_box; do
	encoded=$(pfunct --all --format_path=btf ${align16}.o | grep " ${fn}(")
	verbose_log "BTF: $encoded"
	if [[ -z "$encoded" ]]; then
		error_log "${fn}() is missing from BTF"
		test_fail
	fi
done

test_pass
