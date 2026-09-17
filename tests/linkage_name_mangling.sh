#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Validate that source names remain BTF function names and distinct ELF linkage
# names are retained in whole-function declaration tags.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "Source-language BTF linkage declaration tags."

RUSTC=${RUSTC:-rustc}
CC=${CC:-cc}
CXX=${CXX:-c++}

if ! command -v "$RUSTC" >/dev/null 2>&1; then
	info_log "skip: rustc not available"
	test_skip
fi

if ! command -v "$CC" >/dev/null 2>&1; then
	info_log "skip: C compiler not available"
	test_skip
fi

if ! command -v "${CXX%% *}" >/dev/null 2>&1; then
	info_log "skip: C++ compiler not available"
	test_skip
fi

if ! command -v bpftool >/dev/null 2>&1; then
	info_log "skip: bpftool not available"
	test_skip
fi

if ! command -v readelf >/dev/null 2>&1; then
	info_log "skip: readelf not available"
	test_skip
fi

rust_src="$outdir/rust.rs"
rust_obj="$outdir/rust.o"
rust_btf="$outdir/rust.btf"

printf '%s\n' \
	'pub fn rust_btf_linkage_name(value: u32) -> u32 {' \
	'    value + 1' \
	'}' > "$rust_src"

if ! "$RUSTC" --crate-name rust_btf_linkage --crate-type lib --emit=obj \
	-C debuginfo=2 -C opt-level=0 -o "$rust_obj" "$rust_src" >"$outdir/rustc.log" 2>&1; then
	error_log "FAIL: rustc could not compile Rust linkage fixture"
	cat "$outdir/rustc.log" >&2
	test_fail
fi

linkage_name=$(nm -a "$rust_obj" 2>/dev/null | awk '$NF ~ /^(_Z|_R)/ { print $NF; exit }')
if [ -z "$linkage_name" ]; then
	error_log "FAIL: could not find the Rust linkage symbol"
	test_fail
fi

# Rust producers are free to choose the DW_AT_name spelling.  Read it from
# the DIE associated with the symbol rather than hard-coding a rustc-specific
# spelling in this test.
dwarf_name=$(readelf --debug-dump=info "$rust_obj" 2>/dev/null |
	awk -v linkage="$linkage_name" '
		$0 ~ "DW_AT_linkage_name" && index($0, linkage) { found=1; next }
		found && /DW_AT_name/ { sub(/^.*: /, ""); print; exit }
	')
if [ -z "$dwarf_name" ]; then
	error_log "FAIL: could not find DW_AT_name for Rust linkage symbol"
	test_fail
fi

if ! pahole --btf_encode_detached="$rust_btf" "$rust_obj" >"$outdir/pahole-rust.log" 2>&1; then
	error_log "FAIL: pahole could not encode Rust BTF"
	cat "$outdir/pahole-rust.log" >&2
	test_fail
fi

if ! check_bpftool_btf_support "$rust_btf"; then
	info_log "skip: bpftool cannot dump BTF declaration tags"
	test_skip
fi

rust_dump=$(bpftool btf dump file "$rust_btf" 2>/dev/null)
if ! printf '%s\n' "$rust_dump" | grep -Fq "FUNC '$dwarf_name'"; then
	error_log "FAIL: Rust BTF function does not use DW_AT_name"
	printf '%s\n' "$rust_dump" >&2
	test_fail
fi
if ! printf '%s\n' "$rust_dump" | grep -Fq "DECL_TAG 'rust:linkage:$linkage_name'"; then
	error_log "FAIL: Rust BTF is missing the linkage declaration tag"
	printf '%s\n' "$rust_dump" >&2
	test_fail
fi

# Check the generic language namespace with a C++ linkage name too.
cpp_src="$outdir/cpp.cc"
cpp_obj="$outdir/cpp.o"
cpp_btf="$outdir/cpp.btf"
printf '%s\n' \
	'unsigned int cxx_btf_linkage_name(unsigned int value) { return value + 1; }' > "$cpp_src"

if ! "$CXX" -std=c++14 -g -O0 -c -o "$cpp_obj" "$cpp_src" >"$outdir/cxx.log" 2>&1; then
	error_log "FAIL: C++ compiler could not compile linkage fixture"
	cat "$outdir/cxx.log" >&2
	test_fail
fi

cpp_linkage_name=$(nm -a "$cpp_obj" 2>/dev/null | awk '$NF ~ /^_Z/ { print $NF; exit }')
if [ -z "$cpp_linkage_name" ]; then
	error_log "FAIL: could not find the C++ linkage symbol"
	test_fail
fi

cpp_dwarf_name=$(readelf --debug-dump=info "$cpp_obj" 2>/dev/null |
	awk -v linkage="$cpp_linkage_name" '
		/DW_TAG_subprogram/ { name="" }
		/DW_AT_name/ { name=$0; sub(/^.*: /, "", name) }
		$0 ~ "DW_AT_linkage_name" && index($0, linkage) { print name; exit }
	')
if [ -z "$cpp_dwarf_name" ]; then
	error_log "FAIL: could not find DW_AT_name for C++ linkage symbol"
	test_fail
fi

if ! pahole --btf_encode_detached="$cpp_btf" "$cpp_obj" >"$outdir/pahole-cpp.log" 2>&1; then
	error_log "FAIL: pahole could not encode C++ BTF"
	cat "$outdir/pahole-cpp.log" >&2
	test_fail
fi

cpp_dump=$(bpftool btf dump file "$cpp_btf" 2>/dev/null)
if ! printf '%s\n' "$cpp_dump" | grep -Fq "FUNC '$cpp_dwarf_name'"; then
	error_log "FAIL: C++ BTF function does not use DW_AT_name"
	printf '%s\n' "$cpp_dump" >&2
	test_fail
fi
if ! printf '%s\n' "$cpp_dump" | grep -Fq "DECL_TAG 'c++14:linkage:$cpp_linkage_name'"; then
	error_log "FAIL: C++ BTF is missing the linkage declaration tag"
	printf '%s\n' "$cpp_dump" >&2
	test_fail
fi

# A C compilation unit must not gain Rust linkage tags.
c_src="$outdir/c.c"
c_obj="$outdir/c.o"
c_btf="$outdir/c.btf"
printf '%s\n' 'unsigned int c_btf_linkage_name(unsigned int value) { return value + 1; }' > "$c_src"

if ! "$CC" -g -O0 -c -o "$c_obj" "$c_src" >"$outdir/cc.log" 2>&1 ||
	! pahole --btf_encode_detached="$c_btf" "$c_obj" >"$outdir/pahole-c.log" 2>&1; then
	error_log "FAIL: could not encode C control fixture"
	test_fail
fi

c_dump=$(bpftool btf dump file "$c_btf" 2>/dev/null)
if printf '%s\n' "$c_dump" | grep -Fq 'rust:linkage:'; then
	error_log "FAIL: C BTF unexpectedly contains a Rust linkage tag"
	printf '%s\n' "$c_dump" >&2
	test_fail
fi

test_pass
