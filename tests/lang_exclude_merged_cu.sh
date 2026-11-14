#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Test --lang_exclude when CUs are merged, as for LTO objects: excluding the
# language of the first CU must not drop the CUs that follow it.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Language filtering of merged CUs."

CC=${CC:-gcc}
CXX=${CXX:-g++}
LD=${LD:-ld}
for tool in "$CC" "$CXX" "$LD"; do
	if ! command -v "${tool%% *}" > /dev/null 2>&1; then
		info_log "skip: $tool not available"
		test_skip
	fi
done

cat > "$outdir/first.cpp" << 'EOF'
struct cpp_only {
	int	a;
};

struct cpp_only cpp_var;
EOF

cat > "$outdir/second.c" << 'EOF'
struct c_only {
	int	b;
};

struct c_only c_var;
EOF

obj="$outdir/merged.o"

if ! $CXX -g -c -o "$outdir/first.o" "$outdir/first.cpp" 2>/dev/null ||
   ! $CC -g -c -o "$outdir/second.o" "$outdir/second.c" 2>/dev/null ||
   ! $LD -r -o "$obj" "$outdir/first.o" "$outdir/second.o" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

output=$(pahole --btf_features=force_cu_merging -F dwarf "$obj" 2>/dev/null)
if ! echo "$output" | grep -q "struct cpp_only" ||
   ! echo "$output" | grep -q "struct c_only"; then
	error_log "FAIL: merged CU lacks types without --lang_exclude"
	test_fail
fi

output=$(pahole --btf_features=force_cu_merging -F dwarf \
	--lang_exclude=c++,c++03,c++11,c++14 "$obj" 2>/dev/null)
if echo "$output" | grep -q "struct cpp_only"; then
	error_log "FAIL: --lang_exclude=c++ kept the C++ CU"
	test_fail
fi
if ! echo "$output" | grep -q "struct c_only"; then
	error_log "FAIL: --lang_exclude=c++ dropped the C CU merged after it"
	test_fail
fi

test_pass
