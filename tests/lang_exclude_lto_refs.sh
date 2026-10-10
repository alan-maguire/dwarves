#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Test --lang_exclude on clang LTO objects, where a kept CU refers to a type
# in an excluded CU: LLVM emits int once, in the first CU that uses it.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)

trap cleanup EXIT

title_log "Language filtering of LTO CUs that refer to excluded CUs."

for tool in clang clang++ ld.lld; do
	if ! command -v $tool > /dev/null 2>&1; then
		info_log "skip: $tool not available"
		test_skip
	fi
done

echo 'char zero_c;' > "$outdir/zero.c"

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

obj="$outdir/lto.so"

if ! clang -flto -g -c -o "$outdir/zero.o" "$outdir/zero.c" 2>/dev/null ||
   ! clang++ -flto -g -c -o "$outdir/first.o" "$outdir/first.cpp" 2>/dev/null ||
   ! clang -flto -g -c -o "$outdir/second.o" "$outdir/second.c" 2>/dev/null ||
   ! clang -flto -fuse-ld=lld -shared -o "$obj" "$outdir/zero.o" \
	"$outdir/first.o" "$outdir/second.o" 2>/dev/null; then
	error_log "FAIL: compilation failed"
	test_fail
fi

lang_exclude=c++,c++03,c++11,c++14
btf="$outdir/lto.btf"

check()
{
	if [ $1 -ne 0 ]; then
		error_log "FAIL: $2: pahole failed"
		test_fail
	fi
	if echo "$3" | grep -q "struct cpp_only"; then
		error_log "FAIL: $2: --lang_exclude=c++ kept the C++ CU"
		test_fail
	fi
	if ! echo "$3" | grep -Eq "^[[:space:]]+int[[:space:]]+b;"; then
		error_log "FAIL: $2: c_only.b lost its type, int from the C++ CU"
		test_fail
	fi
}

output=$(pahole -F dwarf --lang_exclude=$lang_exclude "$obj" 2>/dev/null)
check $? "DWARF" "$output"

pahole -J --btf_encode_detached="$btf" --lang_exclude=$lang_exclude "$obj" > /dev/null 2>&1
output=$(pahole -F btf "$btf" 2>/dev/null)
check $? "BTF" "$output"

test_pass
