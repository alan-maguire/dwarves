#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Check that pfunct can print btf_decl_tags read from BTF

source test_lib.sh

outdir=$(make_tmpdir)
tmpobj=$(make_tmpobj)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Check that pfunct can print btf_decl_tags read from BTF."

# gcc 16+ supports decl tags via DW_TAG_GNU_annotation (gcc commit ac7027f180b).
# Use gcc if available and version >= 16, otherwise fall back to clang.

GCC=${GCC:-gcc}
CLANG=${CLANG:-clang}

use_gcc=0
if command -v $GCC > /dev/null; then
	gcc_ver=$($GCC -dumpversion 2>/dev/null | cut -d. -f1)
	if [ "$gcc_ver" -ge 16 ] 2>/dev/null; then
		use_gcc=1
	fi
fi

src=$(cat <<EOF
#define __tag(x) __attribute__((btf_decl_tag(#x)))

__tag(a) __tag(b) __tag(c) void foo(void) {}
__tag(a) __tag(b)          void bar(void) {}
__tag(a)                   void buz(void) {}

EOF
)

if [ "$use_gcc" -eq 1 ]; then
	info_log "Using $GCC (version $gcc_ver) for btf_decl_tag test"
	echo "$src" | $GCC -c -g -x c -o $tmpobj - 2>/dev/null
	pahole -J $tmpobj 2>/dev/null
elif command -v $CLANG > /dev/null; then
	info_log "Using $CLANG for btf_decl_tag test"
	echo "$src" | $CLANG --target=bpf -c -g -x c -o $tmpobj -
else
	error_log "Need gcc >= 16 or clang for test $0"
	test_fail
fi

# tags order is not guaranteed
sort_tags=$(cat <<EOF
{
match(\$0,/^(.*) (void .*)/,tags_and_proto);
tags  = tags_and_proto[1];
proto = tags_and_proto[2];
split(tags, tags_arr ,/ /);
asort(tags_arr);
for (t in tags_arr) printf "%s ", tags_arr[t];
print proto;
}
EOF
)

expected=$(cat <<EOF
a b c void foo(void);
a b void bar(void);
a void buz(void);
EOF
)

out=$(pfunct -P -F btf $tmpobj | awk "$sort_tags" | sort)
d=$(diff -u <(echo "$expected") <(echo "$out"))

if [[ "$d" == "" ]]; then
	test_pass
else
	error_log "pfunct output does not match expected:"
	info_log "$d"
	info_log
	info_log "Complete output:"
	info_log "$out"
	test_fail
fi
