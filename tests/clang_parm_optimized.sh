#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

source test_lib.sh

outdir=$(make_tmpdir)

# Comment this out to save test data.
trap cleanup EXIT

title_log "Validation of BTF encoding of true_signatures."

clang_true="${outdir}/clang_true"
CC=$(which clang 2>/dev/null)

if [[ -z "$CC" ]]; then
	info_log "skip: clang not available"
	test_skip
fi

cat > ${clang_true}.c << EOF
struct t { int a; };
__attribute__((noinline)) char *tar(struct t *a, struct t *d)
{
	if (a->a == d->a)
		return (char *)10;
	else
		return (char *)0;
}

__attribute__((noinline)) static char * foo(struct t *a, int b, struct t *d)
{
	return tar(a, d);
}

__attribute__((noinline)) char *bar(struct t *a, struct t *d)
{
	return foo(a, 1, d);
}

struct t p1, p2;
int main()
{
	return !!bar(&p1, &p2);
}
EOF

CFLAGS="$CFLAGS -g -O2"
${CC} ${CFLAGS} -o $clang_true ${clang_true}.c
if [[ $? -ne 0 ]]; then
	error_log "Could not compile ${clang_true}.c"
	test_fail
fi
LLVM_OBJCOPY=objcopy pahole -J --btf_features=+true_signature $clang_true
if [[ $? -ne 0 ]]; then
	error_log "Could not encode BTF for $clang_true"
	test_fail
fi

btf_optimized=$(pfunct --all --format_path=btf $clang_true |grep "foo")
if [[ -z "$btf_optimized" ]]; then
	info_log "skip: no optimizations applied."
	test_skip
fi

btf_cmp=$btf_optimized
dwarf=$(pfunct --all $clang_true |grep "foo")

if [[ -n "$VERBOSE" ]]; then
	printf "   BTF: %s  DWARF: %s\n" "$btf_optimized" "$dwarf"
fi

if [[ "$btf_cmp" == "$dwarf" ]]; then
	error_log "BTF and DWARF signatures should be different and they are not: BTF: $btf_optimized ; DWARF $dwarf"
	test_fail
fi
test_pass
