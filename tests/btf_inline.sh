#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

script_dir=$(dirname "$0")
source "$script_dir/test_lib.sh"

outdir=$(make_tmpdir)
trap cleanup EXIT

title_log "Validation of additive inline BTF encoding."

CC=${CC:-gcc}
if ! command -v "$CC" >/dev/null 2>&1; then
	info_log "skip: gcc not available"
	test_skip
fi

if ! pahole --supported_btf_features | tr ',' '\n' | grep -Fxq inline; then
	info_log "skip: pahole was built without BTF location support"
	test_skip
fi

src=${outdir}/btf_inline.c
obj=${outdir}/btf_inline
btf=${outdir}/btf_inline.btf

cat > "$src" <<'EOF'
/* Keep the inline functions small enough to guarantee inlining at -O2. */
static inline int scale(int value, int factor)
{
	return value * factor;
}

static inline int add_bias(int value, int bias)
{
	return scale(value, 2) + bias;
}

static volatile int inline_bias;

static inline int add_global(void)
{
	return inline_bias;
}

static inline int combine(int value, int bias)
{
	return add_bias(value, bias) + add_global();
}

__attribute__((noinline)) int wrapper_once(int value, int bias)
{
	return combine(value, bias);
}

__attribute__((noinline)) int wrapper_twice(int value, int bias)
{
	return combine(value, bias) + combine(bias, value);
}

int main(void)
{
	return wrapper_once(1, 3) + wrapper_twice(2, 4);
}
EOF

"$CC" -g -O2 -o "$obj" "$src"
if [[ $? -ne 0 ]]; then
	error_log "Could not compile $src"
	test_fail
fi

if ! pahole --btf_features=default,inline --btf_encode_detached="$btf" "$obj"; then
	error_log "Could not encode inline BTF for $obj"
	test_fail
fi

# Inline location BTF augments the ordinary BTF_KIND_FUNC records for the
# non-inline wrappers. It must cover nested calls, a constant parameter, a
# no-argument inline function, and multiple call sites of the same inline.
if ! pfunct --all --format_path=btf "$btf" 2>/dev/null | grep -Fq "int wrapper_once(int value, int bias);"; then
	error_log "wrapper_once() is missing from inline BTF"
	test_fail
fi

if ! pfunct --all --format_path=btf "$btf" 2>/dev/null | grep -Fq "int wrapper_twice(int value, int bias);"; then
	error_log "wrapper_twice() is missing from inline BTF"
	test_fail
fi

if ! pfunct --all --format_path=btf "$btf" 2>/dev/null | grep -Fq "inline int scale(int value, int factor);"; then
	error_log "scale() inline location is missing from BTF"
	test_fail
fi

if ! pfunct --all --format_path=btf "$btf" 2>/dev/null | grep -Fq "inline int add_bias(int value, int bias);"; then
	error_log "add_bias() inline location is missing from BTF"
	test_fail
fi

if ! pfunct --all --format_path=btf "$btf" 2>/dev/null | grep -Fq "inline int add_global(void);"; then
	error_log "add_global() inline location is missing from BTF"
	test_fail
fi

if ! pfunct --all --format_path=btf "$btf" 2>/dev/null | grep -Fq "inline int combine(int value, int bias);"; then
	error_log "combine() inline location is missing from BTF"
	test_fail
fi

if command -v bpftool >/dev/null 2>&1; then
	locsec_vlen=$(bpftool btf dump file "$btf" format raw 2>/dev/null |
		     sed -n 's/.*LOCSEC .*vlen=\([0-9][0-9]*\).*/\1/p')
	if [[ -z "$locsec_vlen" || "$locsec_vlen" -lt 2 ]]; then
		error_log "multiple inline call sites are missing from LOCSEC"
		test_fail
	fi
fi

test_pass
