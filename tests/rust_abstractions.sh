#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
#
# Test BTF encoding of Rust abstractions.
#
# Compile Rust code using a range of language abstractions, encode BTF from
# its DWARF and check that each abstraction can be rendered from BTF:
#
#  1. structs, tuple structs, unit structs, generics (including const and
#     nested generics), PhantomData, unions, C-like enums (including 64-bit
#     signed ones), nested modules, slices, str, trait objects, references,
#     raw and function pointers, arrays, char and i128 are rendered from BTF
#     as they are from DWARF;
#  2. BTF has no representation of Rust sum types, so enums with fields,
#     Option and Result are encoded as memberless structs of the same size,
#     and the structs describing their variants are encoded;
#  3. tuples and types with commas in their names (which pahole -C cannot
#     select) are encoded;
#  4. structs can be reorganized from detached BTF;
#  5. functions referencing Rust types are encoded.
#
# BTF is both encoded in place and detached.  The pointer size of detached
# BTF cannot be taken from the ELF class, and Rust BTF has no "long" type for
# libbpf to determine it from, so rendering detached BTF also checks that
# pahole determines the pointer size of such BTF.
#
# Set PAHOLE or RUSTC to use non-default tools.

. "$(dirname "$0")/test_lib.sh"
outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "Rust abstractions in BTF."

PAHOLE=${PAHOLE:-pahole}
RUSTC=${RUSTC:-rustc}

for tool in "$PAHOLE" "$RUSTC" bpftool; do
	if ! command -v "$tool" > /dev/null 2>&1; then
		info_log "skip: $tool not available"
		test_skip
	fi
done

src="$outdir/rust_abstractions.rs"
dwarf_obj="$outdir/rust_abstractions.o"
btf_obj="$outdir/rust_abstractions_btf.o"
btf_detached="$outdir/rust_abstractions.btf"

cat > "$src" << 'EOF'
#![no_std]
#![allow(dead_code)]

use core::marker::PhantomData;
use core::mem::ManuallyDrop;

pub struct RaRecord {
    pub number: u64,
    pub enabled: bool,
    pub ratio: f32,
}

pub struct RaTuple(pub u16, pub i64);

pub struct RaUnit;

pub struct RaGeneric<T> {
    pub value: T,
    pub count: usize,
}

pub struct RaConst<const N: usize> {
    pub data: [u8; N],
}

pub struct RaPhantom<T> {
    pub raw: u32,
    pub marker: PhantomData<T>,
}

#[repr(C)]
pub union RaUnion {
    pub number: u32,
    pub bytes: [u8; 4],
    pub wide: ManuallyDrop<u64>,
}

#[repr(u8)]
pub enum RaFieldless {
    First = 1,
    Second = 2,
    Third = 7,
}

#[repr(i64)]
pub enum RaWide {
    Low = -1,
    High = 1 << 40,
}

pub enum RaChoice {
    Empty,
    Number(u32),
    Pair(u16, u64),
    Named { x: i8, y: i32 },
}

pub enum RaNiche<'a> {
    Nothing,
    Something(&'a u32),
}

pub trait RaTrait {
    fn get(&self) -> u32;
}

impl RaTrait for RaRecord {
    fn get(&self) -> u32 {
        self.number as u32
    }
}

pub mod inner {
    pub struct RaNested {
        pub depth: u8,
    }
}

pub struct RaAbstractions<'a> {
    pub record: RaRecord,
    pub tuple: RaTuple,
    pub tuple_type: (u8, u32),
    pub unit: RaUnit,
    pub generic: RaGeneric<i16>,
    pub const_generic: RaConst<4>,
    pub nested_generic: RaGeneric<RaGeneric<u8>>,
    pub phantom: RaPhantom<u64>,
    pub union_: RaUnion,
    pub fieldless: RaFieldless,
    pub wide: RaWide,
    pub choice: RaChoice,
    pub niche: RaNiche<'a>,
    pub option: Option<u32>,
    pub option_ref: Option<&'a RaRecord>,
    pub result: Result<u32, i8>,
    pub array: [u16; 3],
    pub records: [RaRecord; 2],
    pub slice: &'a [u32],
    pub string: &'a str,
    pub reference: &'a RaRecord,
    pub mut_reference: &'a mut u64,
    pub raw: *const u8,
    pub raw_mut: *mut RaRecord,
    pub dyn_trait: &'a dyn RaTrait,
    pub func: fn(u32) -> u32,
    pub nested: inner::RaNested,
    pub char_: char,
    pub i128_: i128,
}

#[no_mangle]
pub extern "C" fn ra_use(a: &RaAbstractions) -> u32 {
    a.record.number as u32
}
EOF

if ! "$RUSTC" --crate-name rust_abstractions --crate-type lib --emit=obj \
	-C debuginfo=2 -C opt-level=0 -o "$dwarf_obj" "$src" > "$outdir/rustc.log" 2>&1; then
	error_log "FAIL: $RUSTC could not compile the Rust source"
	cat "$outdir/rustc.log" >&2
	test_fail
fi

cp "$dwarf_obj" "$btf_obj"
if ! "$PAHOLE" -J "$btf_obj" > "$outdir/encode.log" 2>&1; then
	error_log "FAIL: $PAHOLE -J could not encode BTF"
	cat "$outdir/encode.log" >&2
	test_fail
fi

if ! "$PAHOLE" --btf_encode_detached="$btf_detached" "$dwarf_obj" > "$outdir/encode-detached.log" 2>&1; then
	error_log "FAIL: $PAHOLE could not encode detached BTF"
	cat "$outdir/encode-detached.log" >&2
	test_fail
fi

raw="$outdir/btf.raw"
if ! bpftool btf dump file "$btf_obj" format raw > "$raw" 2>&1; then
	error_log "FAIL: bpftool could not dump BTF"
	cat "$raw" >&2
	test_fail
fi

# render <format> <object> <type>: pahole -C output for type
render()
{
	"$PAHOLE" -F "$1" -C "$3" "$2" 2>&1
}

# Drop the parts of pahole output that differ between DWARF and BTF but do
# not describe the layout: alignment attributes (not encoded in BTF), C++
# access specifiers and summary comments.
normalize()
{
	sed -E -e 's/ __attribute__\(\(__aligned__\([0-9]+\)\)\)//g' \
	       -e '/^[[:space:]]*public:[[:space:]]*$/d' \
	       -e '/^[[:space:]]*\/\*.*\*\/[[:space:]]*$/d' \
	       -e '/^[[:space:]]*$/d' \
	       -e 's/[[:space:]]+/ /g'
}

# compare <BTF file> <type>: check that type is rendered from the BTF file
# as it is from DWARF.
compare()
{
	render dwarf "$dwarf_obj" "$2" > "$outdir/dwarf.txt"
	render btf "$1" "$2" > "$outdir/btf.txt"
	if ! grep -q "^[a-z]* $(printf '%s' "$2" | sed 's/[][\.*^$]/\\&/g') {" "$outdir/btf.txt"; then
		error_log "FAIL: could not render '$2' from BTF in $(basename "$1")"
		cat "$outdir/btf.txt" >&2
		test_fail
	fi
	normalize < "$outdir/dwarf.txt" > "$outdir/dwarf.norm"
	normalize < "$outdir/btf.txt" > "$outdir/btf.norm"
	if ! cmp -s "$outdir/dwarf.norm" "$outdir/btf.norm"; then
		error_log "FAIL: '$2' rendered from BTF in $(basename "$1") differs from DWARF"
		diff -u "$outdir/dwarf.norm" "$outdir/btf.norm" >&2
		test_fail
	fi
}

# 1. Types are rendered from BTF as they are from DWARF.
for btf in "$btf_obj" "$btf_detached"; do
	for type in RaRecord RaTuple RaUnit 'RaGeneric<i16>' 'RaConst<4>' \
		    'RaGeneric<rust_abstractions::RaGeneric<u8>>' 'RaPhantom<u64>' \
		    RaUnion RaFieldless RaWide RaNested '&[u32]' '&str' \
		    '&dyn rust_abstractions::RaTrait' RaAbstractions; do
		compare "$btf" "$type"
	done
done

# raw_type <KIND 'name'>: BTF raw dump line for the type
raw_type()
{
	grep -F "] $1 " "$raw"
}

expect_raw()
{
	line=$(raw_type "$1")
	if [ -z "$line" ]; then
		error_log "FAIL: BTF is missing $1"
		test_fail
	fi
	shift
	for expected in "$@"; do
		case " $line " in
		*" $expected "*)
			;;
		*)
			error_log "FAIL: BTF has '$line', expected $expected"
			test_fail
			;;
		esac
	done
}

# dwarf_size <type>: size of the type in DWARF; variants of sum types are
# rendered as nested structs whose summaries precede the type's summary.
dwarf_size()
{
	render dwarf "$dwarf_obj" "$1" | sed -n 's/^[[:space:]]*\/\* size: \([0-9]*\),.*/\1/p' | tail -1
}

# 2. Sum types are memberless structs of the same size, along with their
# variant structs.
for type in RaChoice RaNiche 'Option<u32>'; do
	size=$(dwarf_size "$type")
	if [ -z "$size" ]; then
		error_log "FAIL: could not determine the DWARF size of '$type'"
		test_fail
	fi
	expect_raw "STRUCT '$type'" "size=$size" "vlen=0"
done
expect_raw "STRUCT 'Result<u32, i8>'" "vlen=0"
expect_raw "STRUCT 'Option<&rust_abstractions::RaRecord>'" "vlen=0"
for btf in "$btf_obj" "$btf_detached"; do
	for type in Empty Number Pair Named Nothing Something Ok Err; do
		compare "$btf" "$type"
	done
done

# 3. Tuples; their layout is checked as part of RaAbstractions above.
expect_raw "STRUCT '(u8, u32)'" "size=8" "vlen=2"

# 4. Reorganizing uses the pointer size; it must not fail for detached BTF.
if ! "$PAHOLE" -F btf --reorganize -C RaAbstractions "$btf_detached" > "$outdir/reorganize.txt" 2>&1 ||
   ! grep -q "^struct RaAbstractions {" "$outdir/reorganize.txt"; then
	error_log "FAIL: could not reorganize RaAbstractions from detached BTF"
	cat "$outdir/reorganize.txt" >&2
	test_fail
fi

# 5. Functions referencing Rust types.
proto=$(raw_type "FUNC 'ra_use'" | sed -n 's/.* type_id=\([0-9]*\).*/\1/p')
param=$(grep -A1 "^\[$proto\] FUNC_PROTO " "$raw" | sed -n "s/^[[:space:]]*'a' type_id=\([0-9]*\)$/\1/p")
target=$(grep "^\[$param\] PTR " "$raw" | sed -n 's/.* type_id=\([0-9]*\)$/\1/p')
if [ -z "$target" ] || ! grep -q "^\[$target\] STRUCT 'RaAbstractions' " "$raw"; then
	error_log "FAIL: ra_use() is not encoded with a pointer to RaAbstractions"
	grep -E "ra_use|^\[$proto\]" -A2 "$raw" >&2
	test_fail
fi

test_pass
