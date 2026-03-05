#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

outdir=

fail()
{
	# Do not remove test dir; might be useful for analysis
	trap - EXIT
	if [[ -d "$outdir" ]]; then
		echo "Test data is in $outdir"
	fi
	exit 1
}

cleanup()
{
	rm ${outdir}/*
	rmdir $outdir
}

outdir=$(mktemp -d /tmp/clang_true.sh.XXXXXX)

trap cleanup EXIT

echo -n "Validation of BTF encoding of true_signatures: "

clang_true="${outdir}/clang_true"
CC=$(which clang 2>/dev/null)

if [[ -z "$CC" ]]; then
	echo "skip: clang not available"
	exit 2
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

__attribute__((noinline)) static char * foo(struct t *a, int b1, int b2, int b3, int b4, int b5, int b6, struct t *d)
{
        return tar(a, d);
}

__attribute__((noinline)) char *bar(struct t *a, struct t *d)
{
        return foo(a, 1, 2, 3, 4, 5, 6, d);
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
	echo "Could not compile ${clang_true}.c" >& 2
	exit 1
fi
LLVM_OBJCOPY=objcopy pahole -J --btf_features=+true_signature $clang_true
if [[ $? -ne 0 ]]; then
	echo "Could not encode BTF for $clang_true"
	exit 1
fi

btf_optimized=$(pfunct --all --format_path=btf $clang_true |grep "foo")
if [[ -z "$btf_optimized" ]]; then
	echo "skip: no optimizations applied."
	exit 2
fi

btf_cmp=$btf_optimized
dwarf=$(pfunct --all $clang_true |grep "foo")

test -n "$VERBOSE" && printf "\nBTF: $btf_optimized  DWARF: $dwarf \n"

if [[ "$btf_cmp" == "$dwarf" ]]; then
	echo "BTF and DWARF signatures should be different and they are not: BTF: $btf_optimized ; DWARF $dwarf"
	exit 1
else
        echo ""
        echo "  BTF:   $btf_optimized"
        echo "  DWARF: $dwarf"
fi
echo "Ok"
exit 0
