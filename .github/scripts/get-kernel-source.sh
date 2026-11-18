#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Fetch bpf-next kernel source, tolerating failures/stalls of any
# single git host by retrying across mirrors.
#

GITHUB_WORKSPACE=${GITHUB_WORKSPACE:-$(dirname $0)/../..}
DEST=${GITHUB_WORKSPACE}/.kernel
FETCH_TIMEOUT=${FETCH_TIMEOUT:-15m}
ATTEMPTS=${ATTEMPTS:-3}

# "URL REF" pairs, tried in order.  kernel-patches/bpf bpf-next_base tracks
# bpf-next master plus BPF CI commits, and is github-to-github so is the
# first fallback.
MIRRORS=(
	"https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git master"
	"https://github.com/kernel-patches/bpf.git bpf-next_base"
	"https://kernel.googlesource.com/pub/scm/linux/kernel/git/bpf/bpf-next.git master"
)

git init -q "$DEST" && cd "$DEST" || exit 1
# Abort stalled transfers (< 1KB/s for 60s) rather than hanging until
# the job times out, so we move on to the next mirror.
git config http.lowSpeedLimit 1000
git config http.lowSpeedTime 60

for attempt in $(seq 1 $ATTEMPTS); do
	for mirror in "${MIRRORS[@]}"; do
		read -r url ref <<< "$mirror"
		echo "Fetching $ref from $url (attempt $attempt/$ATTEMPTS)"
		if timeout $FETCH_TIMEOUT git fetch --depth=1 "$url" "$ref"; then
			git checkout -q FETCH_HEAD
			echo "Fetched kernel source from $url $ref:"
			git log -1 --oneline
			exit 0
		fi
		echo "Fetch from $url failed"
	done
	if [[ $attempt -lt $ATTEMPTS ]]; then
		sleep $((attempt * 30))
	fi
done

echo "Failed to fetch kernel source from all mirrors" >&2
exit 1
