#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Test replacement of Rust bindgen copies of C types (rust_bindgen_replace).
#
# The kernel's Rust code uses bindgen-generated copies of C structs/unions
# that btf__dedup() cannot merge with the C types.  With
# --btf_features=rust_bindgen_replace, Rust structs/unions with a C
# counterpart of the same name and a compatible layout are replaced by the
# C type before dedup.
#
# The Rust source below mirrors what bindgen generates for the C types
# (bitfield units, __bindgen_anon_N members, __BindgenUnionField unions,
# opaque "_unused"/"_address" structs, explicit padding, flexible arrays,
# keyword renames) without bindgen's helper impls, so only rustc is needed.
#
# Tests:
#  1. without the feature, the Rust copies are encoded alongside the C types
#  2. with the feature, each compatible Rust copy is replaced by the C type,
#     including forward declarations matched by opaque types; Rust types
#     only referenced by replaced types are dropped
#  3. same-named Rust types with a different size or incompatible member
#     layout are kept, as are Rust types without a C counterpart
#  4. references to replaced Rust types (function parameters) resolve to the
#     C types
#  5. -V reports replaced and non-matching types
#  6. split BTF: Rust copies of base BTF types are replaced by the base types
#
# Set PAHOLE, RUSTC, CC or LD to use non-default tools.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "Rust bindgen type replacement."

PAHOLE=${PAHOLE:-pahole}
RUSTC=${RUSTC:-rustc}
CC=${CC:-gcc}
LD=${LD:-ld}

for tool in "$PAHOLE" "$RUSTC" "${CC%% *}" "$LD" bpftool; do
	if ! command -v "$tool" > /dev/null 2>&1; then
		info_log "skip: $tool not available"
		test_skip
	fi
done

if ! "$PAHOLE" --supported_btf_features 2>/dev/null | grep -q rust_bindgen_replace; then
	info_log "skip: $PAHOLE does not support rust_bindgen_replace"
	test_skip
fi

csrc="$outdir/bindgen_c.c"
rsrc="$outdir/bindgen_rust.rs"
cobj="$outdir/bindgen_c.o"
robj="$outdir/bindgen_rust.o"
obj="$outdir/bindgen.o"

cat > "$csrc" << 'EOF'
struct rb_plain { int a; long b; char c; };
struct rb_bits { unsigned int x:3, y:5, z:24; int after; };
struct rb_anon { int kind; union { int i; long l; }; long tail; };
struct rb_opaque { int secret; };
struct rb_fwd;
struct rb_address { int x; };
union rb_union { int i; long l; };
union rb_ufield { int i; long l; };
struct rb_flex { int n; int data[]; };
struct rb_kw { int type; };
struct rb_padded { char c; long l; };
struct rb_size_mismatch { int a; int b; };
struct rb_layout_mismatch { int a; int b; };

void rb_c_use(struct rb_plain *a, struct rb_bits *b, struct rb_anon *c,
	      struct rb_opaque *d, struct rb_fwd *e, struct rb_address *f,
	      union rb_union *g, union rb_ufield *h, struct rb_flex *i,
	      struct rb_kw *j, struct rb_padded *k,
	      struct rb_size_mismatch *l, struct rb_layout_mismatch *m)
{
}
EOF

cat > "$rsrc" << 'EOF'
#![no_std]
#![allow(non_camel_case_types, dead_code)]

use core::ffi::{c_char, c_int, c_long};
use core::marker::PhantomData;

#[repr(C)]
pub struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}

#[repr(C)]
pub struct __IncompleteArrayField<T>(PhantomData<T>, [T; 0]);

#[repr(C)]
pub struct __BindgenUnionField<T>(PhantomData<T>);

#[repr(C)]
pub struct rb_plain {
    pub a: c_int,
    pub b: c_long,
    pub c: c_char,
}

#[repr(C)]
pub struct rb_bits {
    pub _bitfield_align_1: [u32; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 4usize]>,
    pub after: c_int,
}

#[repr(C)]
pub struct rb_anon {
    pub kind: c_int,
    pub __bindgen_anon_1: rb_anon__bindgen_ty_1,
    pub tail: c_long,
}

#[repr(C)]
pub union rb_anon__bindgen_ty_1 {
    pub i: c_int,
    pub l: c_long,
}

#[repr(C)]
pub struct rb_opaque {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct rb_fwd {
    _unused: [u8; 0],
}

#[repr(C)]
pub struct rb_address {
    pub _address: u8,
}

#[repr(C)]
pub union rb_union {
    pub i: c_int,
    pub l: c_long,
}

#[repr(C)]
pub struct rb_ufield {
    pub i: __BindgenUnionField<c_int>,
    pub l: __BindgenUnionField<c_long>,
    pub bindgen_union_field: u64,
}

#[repr(C)]
pub struct rb_flex {
    pub n: c_int,
    pub data: __IncompleteArrayField<c_int>,
}

#[repr(C)]
pub struct rb_kw {
    pub type_: c_int,
}

#[repr(C)]
pub struct rb_padded {
    pub c: c_char,
    pub __bindgen_padding_0: [u8; 7usize],
    pub l: c_long,
}

#[repr(C)]
pub struct rb_size_mismatch {
    pub a: c_int,
}

#[repr(C)]
pub struct rb_layout_mismatch {
    pub a: i16,
    pub b: i16,
    pub c: c_int,
}

#[repr(C)]
pub struct rb_rust_only {
    pub a: c_int,
}

#[no_mangle]
pub extern "C" fn rb_rust_use(
    _a: *mut rb_plain,
    _b: *mut rb_bits,
    _c: *mut rb_anon,
    _d: *mut rb_opaque,
    _e: *mut rb_fwd,
    _f: *mut rb_address,
    _g: *mut rb_union,
    _h: *mut rb_ufield,
    _i: *mut rb_flex,
    _j: *mut rb_kw,
    _k: *mut rb_padded,
    _l: *mut rb_size_mismatch,
    _m: *mut rb_layout_mismatch,
    _n: *mut rb_rust_only,
) {
}
EOF

if ! $CC -g -O0 -c -o "$cobj" "$csrc" > "$outdir/cc.log" 2>&1; then
	error_log "FAIL: $CC could not compile the C source"
	cat "$outdir/cc.log" >&2
	test_fail
fi
if ! "$RUSTC" --crate-type lib --emit=obj -C debuginfo=2 -C opt-level=0 \
	-C panic=abort -o "$robj" "$rsrc" > "$outdir/rustc.log" 2>&1; then
	error_log "FAIL: $RUSTC could not compile the Rust source"
	cat "$outdir/rustc.log" >&2
	test_fail
fi
if ! "$LD" -r -o "$obj" "$cobj" "$robj" > "$outdir/ld.log" 2>&1; then
	error_log "FAIL: $LD could not link the C and Rust objects"
	cat "$outdir/ld.log" >&2
	test_fail
fi

# Rust copies replaced by C types (or forward declarations) when enabled.
replaced="STRUCT:rb_plain STRUCT:rb_bits STRUCT:rb_anon STRUCT:rb_opaque
	  STRUCT:rb_address UNION:rb_union STRUCT:rb_flex STRUCT:rb_kw
	  STRUCT:rb_padded"
# Rust copies kept because their layout does not match the C type.
mismatched="STRUCT:rb_size_mismatch STRUCT:rb_layout_mismatch"

encode()
{
	name=$1
	shift
	if ! "$PAHOLE" "$@" --btf_encode_detached="$outdir/$name.btf" > "$outdir/$name.log" 2>&1; then
		error_log "FAIL: $PAHOLE $* failed"
		cat "$outdir/$name.log" >&2
		test_fail
	fi
}

dump()
{
	name=$1
	shift
	if ! bpftool "$@" btf dump file "$outdir/$name.btf" format raw > "$outdir/$name.raw" 2>&1; then
		error_log "FAIL: bpftool could not dump $name BTF"
		cat "$outdir/$name.raw" >&2
		test_fail
	fi
}

# count <name> <KIND:type name>: number of KIND types with that name
count()
{
	grep -c "^\[[0-9]*\] ${2%%:*} '${2#*:}' " "$outdir/$1.raw"
}

expect_count()
{
	name=$1
	expected=$2
	shift 2
	for t in "$@"; do
		n=$(count "$name" "$t")
		if [ "$n" -ne "$expected" ]; then
			error_log "FAIL: $name BTF has $n ${t%%:*} '${t#*:}', expected $expected"
			test_fail
		fi
	done
}

# param_target <name> <func> <param>: "KIND 'name'" of the type the pointer
# parameter of func points to.
param_target()
{
	awk -v func_name="$2" -v param="$3" '
		/^\[[0-9]+\]/ {
			id = substr($1, 2, length($1) - 2)
			kind[id] = $2; tname[id] = $3; cur = id
			if (match($0, / type_id=[0-9]+/))
				ref[id] = substr($0, RSTART + 9, RLENGTH - 9)
			if ($2 == "FUNC" && $3 == "\047" func_name "\047")
				proto = ref[id]
			next
		}
		{
			split($1, a, "\047")
			if (match($0, /type_id=[0-9]+/))
				params[cur, a[2]] = substr($0, RSTART + 8, RLENGTH - 8)
		}
		END {
			ptr = params[proto, param]
			target = ref[ptr]
			print kind[target], tname[target]
		}' "$outdir/$1.raw"
}

expect_param()
{
	name=$1
	func_name=$2
	param=$3
	expected=$4
	target=$(param_target "$name" "$func_name" "$param")
	if [ "$target" != "$expected" ]; then
		error_log "FAIL: $name BTF $func_name($param) points to '$target', expected '$expected'"
		test_fail
	fi
}

# 1. Without the feature the Rust copies are encoded alongside the C types.
encode off --btf_features=default "$obj"
dump off
expect_count off 2 $replaced $mismatched
expect_count off 1 STRUCT:rb_ufield UNION:rb_ufield STRUCT:rb_fwd \
		 UNION:rb_anon__bindgen_ty_1
# dedup resolves the C forward declaration to the Rust opaque struct.
expect_count off 0 FWD:rb_fwd

# 2. With the feature only the C types remain, and the Rust types only
# referenced by replaced types are gone.
encode on -V --btf_features=default,rust_bindgen_replace "$obj"
dump on
expect_count on 1 $replaced UNION:rb_ufield FWD:rb_fwd
expect_count on 0 STRUCT:rb_ufield STRUCT:rb_fwd UNION:rb_anon__bindgen_ty_1
if grep -E "__bindgen|bindgen_union_field|__Bindgen|__IncompleteArrayField|'type_'" \
	"$outdir/on.raw" > "$outdir/on-bindgen.txt"; then
	error_log "FAIL: bindgen types or members remain in BTF"
	cat "$outdir/on-bindgen.txt" >&2
	test_fail
fi

# 3. Incompatible layouts and Rust-only types are kept.
expect_count on 2 $mismatched
expect_count on 1 STRUCT:rb_rust_only

# 4. The Rust function's parameters point to the C types.
expect_param on rb_rust_use _a "STRUCT 'rb_plain'"
expect_param on rb_rust_use _c "STRUCT 'rb_anon'"
expect_param on rb_rust_use _e "FWD 'rb_fwd'"
expect_param on rb_rust_use _h "UNION 'rb_ufield'"
for param in _a _b _c _d _e _f _g _h _i _j _k; do
	c_target=$(param_target on rb_c_use "${param#_}")
	rust_target=$(param_target on rb_rust_use "$param")
	if [ -z "$c_target" ] || [ "$c_target" != "$rust_target" ]; then
		error_log "FAIL: rb_rust_use($param) points to '$rust_target', rb_c_use(${param#_}) to '$c_target'"
		test_fail
	fi
done

# 5. Verbose output reports replacements and layout mismatches.
for msg in "replacing Rust struct 'rb_plain'" "replacing Rust union 'rb_union'" \
	   "Rust struct 'rb_size_mismatch' .* does not match C layout" \
	   "Rust struct 'rb_layout_mismatch' .* does not match C layout" \
	   "replaced 11 Rust bindgen types with C types"; do
	if ! grep -q "BTF: $msg" "$outdir/on.log"; then
		error_log "FAIL: verbose output is missing '$msg'"
		cat "$outdir/on.log" >&2
		test_fail
	fi
done

# 6. Split BTF: Rust copies of base types are replaced by the base types.
encode base --btf_features=default "$cobj"
encode split --btf_features=default,rust_bindgen_replace \
	--btf_base="$outdir/base.btf" "$robj"
dump split -B "$outdir/base.btf"
dump base
nr_base=$(grep -c '^\[' "$outdir/base.raw")
split_types=$(awk -v nr_base="$nr_base" '
	/^\[[0-9]+\] (STRUCT|UNION|FWD) / {
		id = substr($1, 2, length($1) - 2)
		if (id > nr_base && $3 ~ /^\047rb_/)
			print $2, $3
	}' "$outdir/split.raw" | sort | tr '\n' ' ')
expected_split="STRUCT 'rb_layout_mismatch' STRUCT 'rb_rust_only' STRUCT 'rb_size_mismatch' "
if [ "$split_types" != "$expected_split" ]; then
	error_log "FAIL: split BTF has rb_ types '$split_types', expected '$expected_split'"
	test_fail
fi
# Split BTF dumps only contain split types; resolve against base types too.
cat "$outdir/base.raw" "$outdir/split.raw" > "$outdir/split-all.raw"
expect_param split-all rb_rust_use _a "STRUCT 'rb_plain'"
expect_param split-all rb_rust_use _e "FWD 'rb_fwd'"

test_pass
