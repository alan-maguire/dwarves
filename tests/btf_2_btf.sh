#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (c) 2025, Oracle and/or its affiliates.
#
# Use -gbtf to compile objects with BTF and combine/dedup the
# BTF using pahole; this tests the ability to take BTF as
# input for BTF encoding as well as DWARF.
#

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

outdir=$(mktemp -d /tmp/btf_2_btf.sh.XXXXXX)

trap cleanup EXIT

echo -n "Validation of BTF encoding from cc-generated BTF: "

cat <<EOF > ${outdir}/f1.c
#include <stdlib.h>

enum foo {
	E1,
	E2,
	E3
};

struct bar {
	enum foo f1;
	int f2;
	char *f3;
	void *f4;
};

int baz(struct bar *b)
{
	return b->f2++;
}
EOF
gcc -gbtf -c ${outdir}/f1.c -o ${outdir}/f1.o
if [[ $? -ne 0 ]]; then
	echo "skip: -gbtf not supported or gcc not present"
	exit 1
fi

cat <<EOF > ${outdir}/f2.c
#include <stdlib.h>

enum foo {
        E1,
        E2,
        E3
};

struct bar {
        enum foo f1;
        int f2;
        char *f3;
        void *f4;
};

struct bar2 {
	void *f1;
	int f2[3];
};

int othervar;

void *baz2(struct bar2 *b2, char *o)
{
	if (b2->f2[0] > 2)
		return NULL;
	return o;
}
EOF
gcc -gbtf -c ${outdir}/f2.c -o ${outdir}/f2.o

pahole -J --format_path=btf --btf_features=default --lang_exclude=rust \
	--btf_encode_detached=${outdir}/cc.btf ${outdir}/f1.o ${outdir}/f2.o

for f in ${outdir}/f1.o ${outdir}/cc.btf ; do
	struct=$(pahole $f |grep "struct bar" 2>/dev/null)
	if [[ -z "$struct" ]]; then
		echo "struct bar not found in '$f'"
		fail
	fi
	fns=$(pfunct --all $f |grep baz 2>/dev/null)
	if [[ -z "$fns" ]]; then
		echo "function baz not found in '$f'"
		fail
	fi
done
struct=$(pahole $f |grep "struct bar2" 2>/dev/null)
if [[ -z "$struct" ]]; then
	echo "struct bar2 not found in '$f'"
	fail
fi
fn=$(pfunct --all $f |grep "baz2" 2>/dev/null)
if [[ -z "$fn" ]]; then
	echo "function baz2 not found in '$f'"
	fail
fi

echo "Ok"

exit 0
